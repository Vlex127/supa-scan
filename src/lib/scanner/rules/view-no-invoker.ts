import type { SchemaRule } from "../types";

// By default a Postgres view runs with its owner's privileges, so a view over an
// RLS-protected table can leak rows the caller should not see. security_invoker
// makes the view respect the querying role's RLS instead.
export const viewNoInvoker: SchemaRule = (state) =>
  state.views
    .filter((v) => !v.securityInvoker)
    .map((v) => ({
      ruleId: "VIEW_NO_SECURITY_INVOKER" as const,
      severity: "medium" as const,
      file: v.file,
      line: v.line,
      object: v.qualified,
      evidence: `View ${v.qualified} is not created with security_invoker`,
      remediation:
        "Recreate the view WITH (security_invoker=true). Without it the view is evaluated as " +
        "its owner and bypasses the underlying table's row-level security.",
    }));
