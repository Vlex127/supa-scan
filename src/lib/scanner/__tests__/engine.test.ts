import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runScan } from "../index";
import type { RuleId, ScannedFile } from "../types";

function files(...fs: [string, string][]): ScannedFile[] {
  return fs.map(([path, content]) => ({ path, content }));
}

function ruleIds(findings: { ruleId: RuleId }[]): RuleId[] {
  return findings.map((f) => f.ruleId).sort();
}

// Walk a fixture directory and return its .sql files (paths relative to root).
function loadFixture(name: "insecure" | "secure"): ScannedFile[] {
  const root = fileURLToPath(new URL(`../../../../fixtures/${name}`, import.meta.url));
  const out: ScannedFile[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(`${dir}/${entry.name}`, rel);
      else if (entry.name.endsWith(".sql")) {
        out.push({ path: rel, content: readFileSync(`${dir}/${entry.name}`, "utf8") });
      }
    }
  };
  walk(root, "");
  return out;
}

describe("RLS_DISABLED", () => {
  it("flags an exposed table with no RLS enablement", async () => {
    const findings = await runScan(
      files(["migrations/0001.sql", "create table public.todos (id bigint primary key, title text);"]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("RLS_DISABLED");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].object).toBe("public.todos");
  });

  it("does not flag a table whose RLS is enabled in a later migration", async () => {
    const findings = await runScan(
      files(
        ["migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        ["migrations/0002.sql", "alter table public.todos enable row level security;"],
      ),
    );
    expect(findings).toHaveLength(0);
  });

  it("re-flags a table when a later migration DISABLEs its RLS (ordered state)", async () => {
    const findings = await runScan(
      files(
        ["migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        ["migrations/0002.sql", "alter table public.todos enable row level security;"],
        ["migrations/0003.sql", "alter table public.todos disable row level security;"],
      ),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("RLS_DISABLED");
  });

  it("treats a bare name and a schema-qualified name as the same table", async () => {
    const findings = await runScan(
      files(
        ["migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        ["migrations/0002.sql", "alter table todos enable row level security;"],
      ),
    );
    expect(findings).toHaveLength(0);
  });

  it("flags only the unprotected table when a migration mixes both", async () => {
    const findings = await runScan(
      files([
        "migrations/0001.sql",
        [
          "create table public.todos (id bigint primary key);",
          "create table public.audit_log (id bigint primary key);",
          "alter table public.todos enable row level security;",
        ].join("\n"),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].object).toBe("public.audit_log");
  });

  it("ignores tables in a non-public schema", async () => {
    const findings = await runScan(
      files(["migrations/0001.sql", "create table internal.hidden (id bigint primary key);"]),
    );
    expect(findings).toHaveLength(0);
  });
});

describe("POLICY_PERMISSIVE", () => {
  it("flags a policy whose USING is the constant true", async () => {
    const findings = await runScan(
      files([
        "migrations/0001.sql",
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          'create policy p on public.todos for select to authenticated using (true);',
        ].join("\n"),
      ]),
    );
    expect(findings.some((f) => f.ruleId === "POLICY_PERMISSIVE")).toBe(true);
  });

  it("does not flag a policy bound to the caller", async () => {
    const findings = await runScan(
      files([
        "migrations/0001.sql",
        [
          "create table public.todos (id bigint primary key, user_id uuid);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for select to authenticated",
          "  using ((select auth.uid()) = user_id);",
        ].join("\n"),
      ]),
    );
    expect(findings).toHaveLength(0);
  });
});

describe("POLICY_ANON_WRITE", () => {
  it("flags an INSERT policy granted to anon", async () => {
    const findings = await runScan(
      files([
        "migrations/0001.sql",
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for insert to anon with check (true);",
        ].join("\n"),
      ]),
    );
    const hit = findings.find((f) => f.ruleId === "POLICY_ANON_WRITE");
    expect(hit).toBeDefined();
    expect(hit?.evidence).toContain("anon");
  });

  it("flags a write policy granted to PUBLIC (no TO clause)", async () => {
    const findings = await runScan(
      files([
        "migrations/0001.sql",
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for delete using (id > 0);",
        ].join("\n"),
      ]),
    );
    expect(findings.some((f) => f.ruleId === "POLICY_ANON_WRITE")).toBe(true);
  });

  it("does not flag a read-only authenticated policy", async () => {
    const findings = await runScan(
      files([
        "migrations/0001.sql",
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for select to authenticated using (id > 0);",
        ].join("\n"),
      ]),
    );
    expect(findings).toHaveLength(0);
  });
});

describe("VIEW_NO_SECURITY_INVOKER", () => {
  it("flags a view created without security_invoker", async () => {
    const findings = await runScan(
      files([
        "migrations/0001.sql",
        "create view public.v as select id from public.todos;",
      ]),
    );
    const hit = findings.find((f) => f.ruleId === "VIEW_NO_SECURITY_INVOKER");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("medium");
  });

  it("does not flag a security_invoker view", async () => {
    const findings = await runScan(
      files([
        "migrations/0001.sql",
        "create view public.v with (security_invoker = true) as select id from public.todos;",
      ]),
    );
    expect(findings).toHaveLength(0);
  });
});

describe("SECDEF_NO_SEARCH_PATH", () => {
  const fn = (tail: string): string =>
    [
      "create function public.f() returns int",
      "language plpgsql",
      tail,
      "as $$ begin return 1; end; $$;",
    ].join("\n");

  it("flags a SECURITY DEFINER function without a fixed search_path", async () => {
    const findings = await runScan(
      files(["migrations/0001.sql", fn("security definer")]),
    );
    expect(findings.some((f) => f.ruleId === "SECDEF_NO_SEARCH_PATH")).toBe(true);
  });

  it("does not flag a DEFINER function that pins search_path", async () => {
    const findings = await runScan(
      files(["migrations/0001.sql", fn("security definer set search_path = public, pg_temp")]),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag a SECURITY INVOKER function", async () => {
    const findings = await runScan(files(["migrations/0001.sql", fn("security invoker")]));
    expect(findings).toHaveLength(0);
  });
});

describe("fixtures", () => {
  it("insecure project triggers every v1 rule", async () => {
    const findings = await runScan(loadFixture("insecure"));
    const ids = new Set(findings.map((f) => f.ruleId));
    for (const expected of [
      "RLS_DISABLED",
      "POLICY_PERMISSIVE",
      "POLICY_ANON_WRITE",
      "VIEW_NO_SECURITY_INVOKER",
      "SECDEF_NO_SEARCH_PATH",
    ] satisfies RuleId[]) {
      expect(ids.has(expected)).toBe(true);
    }
  });

  it("secure project yields zero findings", async () => {
    const findings = await runScan(loadFixture("secure"));
    expect(ruleIds(findings)).toEqual([]);
  });
});
