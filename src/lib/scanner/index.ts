import type { Finding, Rule, ScannedFile } from "./types";
import { missingRls } from "./rules/missing-rls";

// The registered rule set. Adding a check means adding a pure function here —
// there is no dynamic loading or eval of scanned content.
const RULES: Rule[] = [missingRls];

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  high: 0,
  medium: 1,
  low: 2,
  info: 3,
};

export function runScan(files: ScannedFile[]): Finding[] {
  const findings = RULES.flatMap((rule) => rule(files));
  return findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );
}

export * from "./types";
