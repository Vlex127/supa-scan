import type { SchemaRule } from "../types";

// SECURITY DEFINER functions run as their owner, ignoring the caller's grants.
// If they don't pin search_path, an attacker who can create objects in an
// earlier schema can shadow an unqualified name the function resolves.
export const secdefNoSearchPath: SchemaRule = (state) =>
  state.functions
    .filter((f) => f.securityDefiner && !f.setsSearchPath)
    .map((f) => ({
      ruleId: "SECDEF_NO_SEARCH_PATH" as const,
      severity: "high" as const,
      file: f.file,
      line: f.line,
      object: f.qualified,
      evidence: `SECURITY DEFINER function ${f.qualified} does not pin search_path`,
      remediation:
        "Add `SET search_path = public, pg_temp` to the function (or schema-qualify every " +
        "reference). A DEFINER function with an unfixed search_path can be hijacked by a " +
        "shadowing object earlier in the path.",
    }));
