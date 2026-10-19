import type { SchemaRule } from "../types";

// A policy whose USING or WITH CHECK predicate is the constant TRUE admits every
// row (or lets every write through) for its role set.
export const policyPermissive: SchemaRule = (state) =>
  state.policies
    .filter((p) => p.usingTrue || p.withCheckTrue)
    .map((p) => {
      const clause =
        p.usingTrue && p.withCheckTrue
          ? "USING (true) and WITH CHECK (true)"
          : p.usingTrue
            ? "USING (true)"
            : "WITH CHECK (true)";
      return {
        ruleId: "POLICY_PERMISSIVE" as const,
        severity: "high" as const,
        file: p.file,
        line: p.line,
        object: p.table,
        evidence: `Policy "${p.name}" on ${p.table} uses ${clause}`,
        remediation:
          "Replace the constant-TRUE predicate with a real check that binds rows to the " +
          "requesting user, e.g. USING ((select auth.uid()) = user_id). A constant-TRUE " +
          "predicate matches every row regardless of owner.",
      };
    });
