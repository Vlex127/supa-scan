import type { RuleId, Severity } from "./types";

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
}

export const RULE_METADATA: Record<RuleId, RuleDescriptor> = {
  RLS_DISABLED: {
    id: "RLS_DISABLED",
    name: "Row-level security not enabled",
    shortDescription: "A public table is created without ROW LEVEL SECURITY.",
    fullDescription:
      "A table in an exposed schema (public, or unqualified) is never given ENABLE ROW LEVEL SECURITY. Without RLS the anon and authenticated roles can read and write every row through the API.",
    defaultSeverity: "high",
  },
  POLICY_PERMISSIVE: {
    id: "POLICY_PERMISSIVE",
    name: "Permissive policy predicate",
    shortDescription: "A write policy uses a constant-TRUE predicate.",
    fullDescription:
      "A write policy whose USING or WITH CHECK clause is the constant TRUE lets any matching role write every row. (A constant-TRUE predicate on a read-only policy is treated as legitimate public reference data and is not flagged.)",
    defaultSeverity: "high",
  },
  POLICY_ANON_WRITE: {
    id: "POLICY_ANON_WRITE",
    name: "Anonymous write policy",
    shortDescription: "A write policy is reachable by anon or PUBLIC.",
    fullDescription:
      "An INSERT/UPDATE/DELETE/ALL policy granted to the anon or PUBLIC role lets anyone write rows without a session.",
    defaultSeverity: "high",
  },
  VIEW_NO_SECURITY_INVOKER: {
    id: "VIEW_NO_SECURITY_INVOKER",
    name: "View without security_invoker",
    shortDescription: "A view is created without security_invoker.",
    fullDescription:
      "A view evaluated as its owner bypasses the underlying table's row-level security. Recreate it WITH (security_invoker=true).",
    defaultSeverity: "medium",
  },
  SECDEF_NO_SEARCH_PATH: {
    id: "SECDEF_NO_SEARCH_PATH",
    name: "SECURITY DEFINER without search_path",
    shortDescription: "A SECURITY DEFINER function does not pin search_path.",
    fullDescription:
      "A SECURITY DEFINER function with an unfixed search_path can be hijacked by a shadowing object earlier in the path. Add SET search_path = public, pg_temp or schema-qualify every reference.",
    defaultSeverity: "high",
  },
  KEY_SERVICE_ROLE_CLIENT: {
    id: "KEY_SERVICE_ROLE_CLIENT",
    name: "service_role key in client code",
    shortDescription: "A service_role key appears in code reachable by a client.",
    fullDescription:
      "The service_role key bypasses row-level security entirely and must never ship to a browser or mobile client. Planned for a later slice.",
    defaultSeverity: "high",
  },
  SECRET_COMMITTED: {
    id: "SECRET_COMMITTED",
    name: "Committed secret",
    shortDescription: "A tracked file appears to contain a secret.",
    fullDescription:
      "A committed .env or tracked file carries a credential. Evidence is masked; the secret value is never echoed. Planned for a later slice.",
    defaultSeverity: "high",
  },
  PARSE_FAILED: {
    id: "PARSE_FAILED",
    name: "File could not be parsed",
    shortDescription: "A file the scanner could not analyze.",
    fullDescription:
      "The SQL parser rejected this file, so none of its contents were analyzed. The scan is marked incomplete; a clean result never hides unread input.",
    defaultSeverity: "high",
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
