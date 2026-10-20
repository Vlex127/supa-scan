import type { RuleId, Severity } from "./types";

// A rule is either a check the scanner can actually perform (implemented), one
// still on the roadmap (planned), or a diagnostic that is never a "finding"
// (PARSE_FAILED). SARIF must only advertise rules that can fire — claiming a rule
// that never produces a result misleads code scanning — so output filters on
// `status === "implemented"`.
export type RuleStatus = "implemented" | "planned" | "diagnostic";

// Static, per-rule descriptors. These are authored here (never derived from the
// scanned repo), so they are safe to embed in SARIF rule metadata and the demo UI.
export interface RuleDescriptor {
  id: RuleId;
  name: string;
  shortDescription: string;
  fullDescription: string;
  // The highest severity this rule can emit, used for SARIF's security-severity
  // property and the rule's default level. A result's own severity is authoritative.
  defaultSeverity: Severity;
  status: RuleStatus;
}

export const RULE_METADATA: Record<RuleId, RuleDescriptor> = {
  RLS_DISABLED: {
    id: "RLS_DISABLED",
    name: "Row-level security not enabled",
    shortDescription: "A public table is created without ROW LEVEL SECURITY.",
    fullDescription:
      "A table in an exposed schema (public, or unqualified) is never given ENABLE ROW LEVEL SECURITY. Without RLS the anon and authenticated roles can read and write every row through the API.",
    defaultSeverity: "high",
    status: "implemented",
  },
  POLICY_PERMISSIVE: {
    id: "POLICY_PERMISSIVE",
    name: "Permissive policy predicate",
    shortDescription: "A write policy uses a constant-TRUE predicate.",
    fullDescription:
      "A write policy whose USING or WITH CHECK clause is the constant TRUE lets any matching role write every row. (A constant-TRUE predicate on a read-only policy is treated as legitimate public reference data and is not flagged.)",
    defaultSeverity: "high",
    status: "implemented",
  },
  POLICY_ANON_WRITE: {
    id: "POLICY_ANON_WRITE",
    name: "Anonymous write policy",
    shortDescription: "A write policy is reachable by anon or PUBLIC.",
    fullDescription:
      "An INSERT/UPDATE/DELETE/ALL policy granted to the anon or PUBLIC role lets anyone write rows without a session.",
    defaultSeverity: "high",
    status: "implemented",
  },
  VIEW_NO_SECURITY_INVOKER: {
    id: "VIEW_NO_SECURITY_INVOKER",
    name: "View without security_invoker",
    shortDescription: "A view is created without security_invoker.",
    fullDescription:
      "A view evaluated as its owner bypasses the underlying table's row-level security. Recreate it WITH (security_invoker=true).",
    defaultSeverity: "medium",
    status: "implemented",
  },
  SECDEF_NO_SEARCH_PATH: {
    id: "SECDEF_NO_SEARCH_PATH",
    name: "SECURITY DEFINER without search_path",
    shortDescription: "A SECURITY DEFINER function does not pin search_path.",
    fullDescription:
      "A SECURITY DEFINER function with an unfixed search_path can be hijacked by a shadowing object earlier in the path. Add SET search_path = public, pg_temp or schema-qualify every reference.",
    defaultSeverity: "high",
    status: "implemented",
  },
  KEY_SERVICE_ROLE_CLIENT: {
    id: "KEY_SERVICE_ROLE_CLIENT",
    name: "service_role key in client code",
    shortDescription: "A service_role key appears in code reachable by a client.",
    fullDescription:
      "The service_role key (or its sb_secret_/sbp_ successors) bypasses row-level security entirely and must never ship to a browser or mobile client. Detected via NEXT_PUBLIC_ variable names, references in \"use client\" files, and any JWT literal whose decoded payload has role: service_role.",
    defaultSeverity: "high",
    status: "planned",
  },
  SECRET_COMMITTED: {
    id: "SECRET_COMMITTED",
    name: "Committed secret",
    shortDescription: "A scanned file appears to contain a credential.",
    fullDescription:
      "A service_role JWT, an sb_secret_/sbp_ Supabase key, a PEM private key, or a key-like assignment in a .env file carries a credential. Evidence is masked; the secret value is never echoed. This rule targets Supabase-specific formats; general secret scanning is gitleaks' job.",
    defaultSeverity: "high",
    status: "planned",
  },
  PARSE_FAILED: {
    id: "PARSE_FAILED",
    name: "File could not be parsed",
    shortDescription: "A file the scanner could not analyze.",
    fullDescription:
      "The SQL parser rejected this file, so none of its contents were analyzed. Reported as a tool-execution notification, not a finding; the scan is marked incomplete.",
    defaultSeverity: "high",
    status: "diagnostic",
  },
};

export const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export const SECURITY_SEVERITY: Record<Severity, string> = {
  high: "8.0",
  medium: "5.5",
  low: "3.5",
  info: "1.0",
};

export function implementedRuleIds(): RuleId[] {
  return (Object.keys(RULE_METADATA) as RuleId[]).filter(
    (id) => RULE_METADATA[id].status === "implemented",
  );
}
