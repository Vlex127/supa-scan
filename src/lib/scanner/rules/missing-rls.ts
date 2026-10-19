import type { Finding, ScannedFile } from "../types";

// CREATE TABLE [IF NOT EXISTS] <name>  — <name> may be schema-qualified and/or quoted.
const CREATE_TABLE_RE =
  /create\s+table\s+(?:if\s+not\s+exists\s+)?(["`]?[\w.]+["`]?)/gi;

// ALTER TABLE [IF EXISTS] <name> ENABLE ROW LEVEL SECURITY
const RLS_ALTER_RE =
  /alter\s+table\s+(?:if\s+exists\s+)?(["`]?[\w.]+["`]?)\s+enable\s+row\s+level\s+security/gi;

// Inline form: CREATE TABLE <name> (...) WITH ( row_security = true )
const INLINE_RLS_RE = /\brow_security\s*=\s*true\b/gi;

function normalize(raw: string): string {
  return raw.replace(/[`"]/g, "").trim().toLowerCase();
}

// A table can be referenced as `todos` or `public.todos`; treat the bare
// (last-segment) name as an alias so the two forms do not read as a mismatch.
function bare(name: string): string {
  const parts = name.split(".");
  return parts[parts.length - 1];
}

function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

export function missingRls(files: ScannedFile[]): Finding[] {
  // Collect every table with RLS enabled anywhere across the migration set.
  const enabled = new Set<string>();
  for (const file of files) {
    const text = file.content;
    for (const m of text.matchAll(RLS_ALTER_RE)) {
      const name = normalize(m[1]);
      enabled.add(name);
      enabled.add(bare(name));
    }
    // Inline WITH (row_security = true): attribute to the nearest preceding
    // CREATE TABLE on the same statement.
    for (const m of text.matchAll(INLINE_RLS_RE)) {
      const before = text.slice(0, m.index);
      const creates = [...before.matchAll(CREATE_TABLE_RE)];
      if (creates.length > 0) {
        const name = normalize(creates[creates.length - 1][1]);
        enabled.add(name);
        enabled.add(bare(name));
      }
    }
  }

  const findings: Finding[] = [];
  for (const file of files) {
    for (const m of file.content.matchAll(CREATE_TABLE_RE)) {
      const name = normalize(m[1]);
      if (enabled.has(name) || enabled.has(bare(name))) continue;
      findings.push({
        ruleId: "RLS_MISSING",
        severity: "high",
        file: file.path,
        line: lineAt(file.content, m.index ?? 0),
        table: name,
        evidence: `CREATE TABLE ${m[1]} with no ENABLE ROW LEVEL SECURITY`,
        remediation:
          "Run `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;` and add least-privilege policies. " +
          "Without RLS, the anon/authenticated roles can read and write the whole table.",
      });
    }
  }
  return findings;
}
