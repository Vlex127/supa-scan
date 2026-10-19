import { describe, expect, it } from "vitest";
import { runScan } from "../index";
import type { ScannedFile } from "../types";

function files(...fs: [string, string][]): ScannedFile[] {
  return fs.map(([path, content]) => ({ path, content }));
}

describe("RLS_MISSING", () => {
  it("flags a created table with no RLS enablement", () => {
    const findings = runScan(
      files([
        "migrations/0001.sql",
        "create table public.todos (id bigint primary key, title text);",
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("RLS_MISSING");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].table).toBe("public.todos");
  });

  it("does not flag a table whose RLS is enabled in a different file", () => {
    const findings = runScan(
      files(
        ["migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        [
          "migrations/0002.sql",
          "alter table public.todos enable row level security;",
        ],
      ),
    );
    expect(findings).toHaveLength(0);
  });

  it("honors the inline WITH (row_security = true) form", () => {
    const findings = runScan(
      files([
        "migrations/0001.sql",
        "create table public.todos (id bigint primary key) with (row_security = true);",
      ]),
    );
    expect(findings).toHaveLength(0);
  });

  it("treats a bare name and a schema-qualified name as the same table", () => {
    const findings = runScan(
      files(
        ["migrations/0001.sql", "create table public.todos (id bigint primary key);"],
        ["migrations/0002.sql", "alter table todos enable row level security;"],
      ),
    );
    expect(findings).toHaveLength(0);
  });

  it("flags only the unprotected table when a migration mixes both", () => {
    const findings = runScan(
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
    expect(findings[0].table).toBe("public.audit_log");
  });
});
