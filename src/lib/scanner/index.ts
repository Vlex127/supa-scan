import type { Finding, ScanResult, ScannedFile, SchemaRule, TextRule } from "./types";
import { buildSchema } from "./schema";
import { rlsDisabled } from "./rules/rls-disabled";
import { policyPermissive } from "./rules/policy-permissive";
import { policyAnonWrite } from "./rules/policy-anon-write";
import { viewNoInvoker } from "./rules/view-no-invoker";
import { secdefNoSearchPath } from "./rules/secdef-no-search-path";
import { keyServiceRoleClient } from "./rules/key-service-role-client";
import { secretCommitted } from "./rules/secret-committed";

// The registered SQL rule set. Adding a check means adding a pure function here;
// there is no dynamic loading, no eval, and no string-keyed dispatch of scanned
// content. Schema rules run on the parsed state; text rules run on raw file text.
const SCHEMA_RULES: SchemaRule[] = [
  rlsDisabled,
  policyPermissive,
  policyAnonWrite,
  viewNoInvoker,
  secdefNoSearchPath,
];

// Source/env rules. Each scopes itself (see scope.ts) so it only inspects the file
// types it understands; SQL files pass through untouched.
const TEXT_RULES: TextRule[] = [keyServiceRoleClient, secretCommitted];

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
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
  const findings = [
    ...SCHEMA_RULES.flatMap((rule) => rule(state)),
    ...TEXT_RULES.flatMap((rule) => rule(files)),
  ].sort(
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
