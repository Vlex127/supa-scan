import type { SchemaRule } from "../types";
import { hasWriteRole } from "../util";

const WRITE_CMDS = new Set(["all", "insert", "update", "delete"]);

// A write policy that the anon or PUBLIC role can reach lets anyone hit the API
// without a session and insert, change, or delete rows.
export const policyAnonWrite: SchemaRule = (state) =>
  state.policies
    .filter((p) => WRITE_CMDS.has(p.cmd) && hasWriteRole(p.roles))
    .map((p) => ({
      ruleId: "POLICY_ANON_WRITE" as const,
      severity: "high" as const,
      file: p.file,
      line: p.line,
      object: p.table,
      evidence: `Policy "${p.name}" grants ${p.cmd.toUpperCase()} to the anon/public role on ${p.table}`,
      remediation:
        "Restrict the policy to an authenticated role (TO authenticated) and bind writes to " +
        "the caller. The anon and PUBLIC roles are reachable without a session, so this " +
        "allows anonymous writes.",
    }));
