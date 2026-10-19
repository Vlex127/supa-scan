// Core types for the scanner. The engine is pure and deterministic: it takes a
// set of already-read files ({path, content}) and returns structured findings.
// It never touches the network, never executes scanned code, and never writes
// to the scanned project. Rule IDs come from a fixed allowlist (no dynamic
// dispatch), mirroring the {field, op, value} discipline used elsewhere.

export type Severity = "high" | "medium" | "low" | "info";

export const RULE_IDS = [
  "RLS_MISSING",
  "POLICY_PERMISSIVE",
  "POLICY_NO_AUTH_BIND",
  "KEY_SERVICE_ROLE_CLIENT",
  "SECRET_COMMITTED",
] as const;

export type RuleId = (typeof RULE_IDS)[number];

export function isRuleId(value: string): value is RuleId {
  return (RULE_IDS as readonly string[]).includes(value);
}

export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  file: string;
  line: number;
  table?: string;
  // A short, sanitized snippet. For secret-bearing rules the matched value is
  // masked before it ever reaches this field — evidence must never carry a key.
  evidence: string;
  remediation: string;
}

export interface ScannedFile {
  path: string;
  content: string;
}

// A rule is a pure function from the whole file set to zero or more findings.
// Rules see all files together because RLS enablement may live in a different
// migration than the CREATE TABLE it protects.
export type Rule = (files: ScannedFile[]) => Finding[];
