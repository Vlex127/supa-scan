import type { SchemaRule, Severity } from "../types";
import { hasWriteRole } from "../util";

const READ_CMDS = new Set(["select"]);

// A constant-TRUE predicate is only dangerous where it guards a WRITE. A read
// policy with USING (true) is the legitimate "public reference data" pattern, so
// it is deliberately not flagged. When it does guard a write, severity follows
// the role: an anonymous/PUBLIC writer is high; an authenticated-only writer is
// medium (the caller still needs a valid session).
export const policyPermissive: SchemaRule = (state) =>
  state.policies
    .filter((p) => !READ_CMDS.has(p.cmd) && (p.usingTrue || p.withCheckTrue))
    .map((p) => {
      const clause =
        p.usingTrue && p.withCheckTrue
          ? "USING (true) and WITH CHECK (true)"
          : p.usingTrue
            ? "USING (true)"
            : "WITH CHECK (true)";
      const severity: Severity = hasWriteRole(p.roles) ? "high" : "medium";
      return {
        ruleId: "POLICY_PERMISSIVE" as const,
        severity,
        file: p.file,
        line: p.line,
        object: p.table,
        evidence: `Policy "${p.name}" uses ${clause} on a ${p.cmd.toUpperCase()} for ${p.table}`,
        remediation:
          "Replace the constant-TRUE predicate with a real check that binds rows to the " +
          "requesting user, e.g. WITH CHECK ((select auth.uid()) = user_id). A constant-TRUE " +
          "predicate lets any matching role write or read every row.",
      };
    });
