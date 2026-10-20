import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runScan } from "../index";
import type { RuleId, ScannedFile } from "../types";

function files(...fs: [string, string][]): ScannedFile[] {
  return fs.map(([path, content]) => ({ path, content }));
}

// One migration body, wrapped as a single scanned file.
function one(sql: string): ScannedFile[] {
  return files(["supabase/migrations/0001_x.sql", sql]);
}

function ids(result: Awaited<ReturnType<typeof runScan>>): RuleId[] {
  return result.findings.map((f) => f.ruleId).sort();
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
    const result = await runScan(one("create table public.todos (id bigint primary key, title text);"));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe("RLS_DISABLED");
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].object).toBe("public.todos");
  });

  it("does not flag a table whose RLS is enabled in a later migration", async () => {
    const result = await runScan(
      files(
        ["supabase/migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        ["supabase/migrations/0002.sql", "alter table public.todos enable row level security;"],
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("re-flags a table when a later migration DISABLEs its RLS (ordered state)", async () => {
    const result = await runScan(
      files(
        ["supabase/migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        ["supabase/migrations/0002.sql", "alter table public.todos enable row level security;"],
        ["supabase/migrations/0003.sql", "alter table public.todos disable row level security;"],
      ),
    );
    expect(ids(result)).toEqual(["RLS_DISABLED"]);
  });

  it("treats a bare name and a schema-qualified name as the same table", async () => {
    const result = await runScan(
      files(
        ["supabase/migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        ["supabase/migrations/0002.sql", "alter table todos enable row level security;"],
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("flags only the unprotected table when a migration mixes both", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "create table public.audit_log (id bigint primary key);",
          "alter table public.todos enable row level security;",
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].object).toBe("public.audit_log");
  });

  it("ignores tables in a non-public schema", async () => {
    const result = await runScan(one("create table internal.hidden (id bigint primary key);"));
    expect(result.findings).toHaveLength(0);
  });

  it("a later DROP TABLE removes the table from state", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "drop table public.todos;",
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("FORCE ROW LEVEL SECURITY after enabling leaves the table clean", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "alter table public.todos force row level security;",
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("preserves quoted-case so an unquoted ALTER does not match a quoted table", async () => {
    const mismatch = await runScan(
      one(
        [
          'create table "public"."Todos" (id bigint primary key);',
          "alter table todos enable row level security;",
        ].join("\n"),
      ),
    );
    expect(ids(mismatch)).toEqual(["RLS_DISABLED"]);
    const match = await runScan(
      one(
        [
          'create table "public"."Todos" (id bigint primary key);',
          'alter table "Todos" enable row level security;',
        ].join("\n"),
      ),
    );
    expect(match.findings).toHaveLength(0);
  });
});

describe("POLICY_PERMISSIVE", () => {
  it("flags a write USING (true) granted to authenticated as medium", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for update to authenticated using (true);",
        ].join("\n"),
      ),
    );
    const hit = result.findings.find((f) => f.ruleId === "POLICY_PERMISSIVE");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("medium");
  });

  it("flags a write predicate granted to anon as high", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for insert to anon with check (true);",
        ].join("\n"),
      ),
    );
    const hit = result.findings.find((f) => f.ruleId === "POLICY_PERMISSIVE");
    expect(hit?.severity).toBe("high");
  });

  it("does NOT flag a read-only policy with USING (true) (public reference data)", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for select to public using (true);",
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("does NOT flag a write policy bound to the caller", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key, user_id uuid);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for insert to authenticated",
          "  with check ((select auth.uid()) = user_id);",
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("a later DROP POLICY removes a permissive policy", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          'create policy "p" on public.todos for update to authenticated using (true);',
          'drop policy "p" on public.todos;',
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("a later ALTER POLICY ... WITH CHECK (true) makes a clean write policy permissive", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          'create policy "p" on public.todos for update to authenticated using (id > 0) with check (id > 0);',
          'alter policy "p" on public.todos with check (true);',
        ].join("\n"),
      ),
    );
    expect(result.findings.map((f) => f.ruleId)).toContain("POLICY_PERMISSIVE");
  });
});

describe("POLICY_ANON_WRITE", () => {
  it("flags an INSERT policy granted to anon", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for insert to anon with check (id > 0);",
        ].join("\n"),
      ),
    );
    const hit = result.findings.find((f) => f.ruleId === "POLICY_ANON_WRITE");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("high");
  });

  it("flags a write policy granted to PUBLIC (no TO clause)", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for delete using (id > 0);",
        ].join("\n"),
      ),
    );
    expect(result.findings.map((f) => f.ruleId)).toContain("POLICY_ANON_WRITE");
  });

  it("does NOT flag a read-only authenticated policy", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          "create policy p on public.todos for select to authenticated using (id > 0);",
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("a later ALTER POLICY ... TO anon flips a clean authenticated policy", async () => {
    const result = await runScan(
      one(
        [
          "create table public.todos (id bigint primary key);",
          "alter table public.todos enable row level security;",
          'create policy "p" on public.todos for insert to authenticated with check (id > 0);',
          'alter policy "p" on public.todos to anon;',
        ].join("\n"),
      ),
    );
    expect(result.findings.map((f) => f.ruleId)).toContain("POLICY_ANON_WRITE");
  });
});

describe("VIEW_NO_SECURITY_INVOKER", () => {
  it("flags a view created without security_invoker", async () => {
    const result = await runScan(one("create view public.v as select id from public.todos;"));
    const hit = result.findings.find((f) => f.ruleId === "VIEW_NO_SECURITY_INVOKER");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("medium");
  });

  it("does not flag a security_invoker view", async () => {
    const result = await runScan(
      one("create view public.v with (security_invoker = true) as select id from public.todos;"),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("a later CREATE OR REPLACE VIEW with security_invoker replaces the flagged view", async () => {
    const result = await runScan(
      one(
        [
          "create view public.v as select id from public.todos;",
          "create or replace view public.v with (security_invoker = true) as select id from public.todos;",
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(0);
  });

  it("a later ALTER VIEW SET (security_invoker = true) clears the finding", async () => {
    const result = await runScan(
      one(
        [
          "create view public.v as select id from public.todos;",
          "alter view public.v set (security_invoker = true);",
        ].join("\n"),
      ),
    );
    expect(result.findings).toHaveLength(0);
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
    const result = await runScan(one(fn("security definer")));
    expect(result.findings.map((f) => f.ruleId)).toContain("SECDEF_NO_SEARCH_PATH");
  });

  it("does not flag a DEFINER function that pins search_path", async () => {
    const result = await runScan(one(fn("security definer set search_path = public, pg_temp")));
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag a SECURITY INVOKER function", async () => {
    const result = await runScan(one(fn("security invoker")));
    expect(result.findings).toHaveLength(0);
  });

  it("a later ALTER FUNCTION ... SET search_path clears the finding", async () => {
    const result = await runScan(
      one([fn("security definer"), "alter function public.f() set search_path = public;"].join("\n")),
    );
    expect(result.findings).toHaveLength(0);
  });
});

describe("scanner robustness", () => {
  it("handles a multi-statement file with comments and block comments", async () => {
    const result = await runScan(
      one(
        [
          "-- initial schema",
          "/* a block comment mentioning create table fake ( x ); */",
          "create table public.a (id bigint primary key);",
          "create table public.b (id bigint primary key);",
          "alter table public.a enable row level security; -- done inline",
        ].join("\n"),
      ),
    );
    expect(ids(result)).toEqual(["RLS_DISABLED"]);
    expect(result.findings[0].object).toBe("public.b");
    expect(result.complete).toBe(true);
  });

  it("records unparseable files as PARSE_FAILED and marks the scan incomplete", async () => {
    const result = await runScan(
      files(
        ["supabase/migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        ["supabase/migrations/0002.sql", "!!! not valid sql @@@ "],
      ),
    );
    expect(result.complete).toBe(false);
    expect(result.parseFailures).toHaveLength(1);
    expect(result.parseFailures[0].ruleId).toBe("PARSE_FAILED");
    expect(result.parseFailures[0].file).toBe("supabase/migrations/0002.sql");
    expect(result.parseFailures[0].category).toBe("syntax_error");
    expect(result.parseFailures[0].line).toBe(1);
    // the other file is still analyzed
    expect(result.findings.map((f) => f.object)).toContain("public.todos");
  });

  it("classifies an unterminated quoted string, places it by line, and echoes nothing", async () => {
    // A secret-shaped value sitting in a broken statement is exactly what a raw
    // parser message would echo. The engine must classify the failure into a fixed
    // category and never carry the offending text anywhere in the result.
    const leak = "LEAKCHECK_PLACEHOLDER";
    const result = await runScan(
      files([
        "supabase/migrations/0003.sql",
        `-- comment\nselect 1;\nselect '${leak}`,
      ]),
    );
    expect(result.complete).toBe(false);
    expect(result.parseFailures).toHaveLength(1);
    expect(result.parseFailures[0].category).toBe("unterminated_string");
    expect(result.parseFailures[0].line).toBe(3); // derived from the parser cursor
    // The failure carries no free-text message field, and the credential appears
    // nowhere in the serializable result.
    expect(result.parseFailures[0]).not.toHaveProperty("message");
    expect(JSON.stringify(result)).not.toContain(leak);
  });

  it("empty and whitespace-only SQL never crash", async () => {
    const result = await runScan(files(["supabase/migrations/0001.sql", "   \n\n"]));
    expect(result.findings).toHaveLength(0);
    expect(result.complete).toBe(true);
  });
});

describe("fixtures", () => {
  it("insecure project triggers every v1 rule and parses completely", async () => {
    const result = await runScan(loadFixture("insecure"));
    expect(result.complete).toBe(true);
    const set = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      "RLS_DISABLED",
      "POLICY_PERMISSIVE",
      "POLICY_ANON_WRITE",
      "VIEW_NO_SECURITY_INVOKER",
      "SECDEF_NO_SEARCH_PATH",
    ] satisfies RuleId[]) {
      expect(set.has(expected)).toBe(true);
    }
    // severity-by-role is exercised in the fixture: at least one medium
    // (authenticated write) and one high (anon write) permissive finding.
    const permissive = result.findings.filter((f) => f.ruleId === "POLICY_PERMISSIVE");
    expect(permissive.map((f) => f.severity).sort()).toEqual(["high", "medium"]);
  });

  it("secure project yields zero findings and is complete", async () => {
    const result = await runScan(loadFixture("secure"));
    expect(result.complete).toBe(true);
    expect(ids(result)).toEqual([]);
  });
});
