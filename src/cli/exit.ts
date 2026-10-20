import type { Finding, Severity } from "../lib/scanner/types";

// Higher rank = more severe. Drives --fail-on comparison and stable ordering.
const RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

// True when a finding meets the configured gate: its severity is at or above
// --fail-on. `failOn` defaults to "info" (fail on any finding) in the CLI.
export function meetsThreshold(finding: Finding, failOn: Severity): boolean {
  return RANK[finding.severity] >= RANK[failOn];
}

export function countAtOrAbove(findings: Finding[], failOn: Severity): number {
  return findings.filter((f) => meetsThreshold(f, failOn)).length;
}

// Exit code contract:
//   0 — complete scan, no finding at or above the gate.
//   1 — complete scan, at least one finding at or above the gate.
//   2 — usage error, tool error, or an INCOMPLETE scan (a parse failure or a
//       schema-relevant file the scanner had to skip). Incomplete outranks
//       findings: the scanner cannot certify a run it could not finish, so it
//       never reports a clean exit over unanalyzed input.
export function computeExitCode(
  complete: boolean,
  findingsAtOrAboveGate: number,
): 0 | 1 | 2 {
  if (!complete) return 2;
  return findingsAtOrAboveGate > 0 ? 1 : 0;
}
