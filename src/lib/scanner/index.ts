import type { Finding, ScanResult, ScannedFile, SchemaRule } from "./types";
import { buildSchema } from "./schema";
import { rlsDisabled } from "./rules/rls-disabled";
import { policyPermissive } from "./rules/policy-permissive";
import { policyAnonWrite } from "./rules/policy-anon-write";
import { viewNoInvoker } from "./rules/view-no-invoker";
import { secdefNoSearchPath } from "./rules/secdef-no-search-path";

// The registered SQL rule set. Adding a check means adding a pure function here;
// there is no dynamic loading, no eval, and no string-keyed dispatch of scanned
// content. Text rules (service_role key, committed secrets) land in slice 3.
const SCHEMA_RULES: SchemaRule[] = [
  rlsDisabled,
  policyPermissive,
  policyAnonWrite,
  viewNoInvoker,
  secdefNoSearchPath,
];

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  high: 0,
  medium: 1,
  low: 2,
  info: 3,
};

function byFileThenLine<T extends { file: string; line: number }>(a: T, b: T): number {
  return a.file.localeCompare(b.file) || a.line - b.line;
}

// Scan a set of already-read files. SQL is parsed to a real Postgres AST and the
// migrations are replayed in path order into a final schema state before rules
// run, so a policy in one file can see a table (and its RLS flag) from another.
// The result separates real findings from files that could not be parsed, and is
// only `complete` when nothing was skipped.
export async function runScan(files: ScannedFile[]): Promise<ScanResult> {
  const { state, parseFailures } = await buildSchema(files);
  const findings = SCHEMA_RULES.flatMap((rule) => rule(state)).sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || byFileThenLine(a, b),
  );
  return {
    complete: parseFailures.length === 0,
    findings,
    parseFailures: parseFailures.sort(byFileThenLine),
  };
}

export * from "./types";
