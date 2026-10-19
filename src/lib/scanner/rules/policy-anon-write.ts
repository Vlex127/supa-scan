import type { RoleRef, SchemaRule } from "../types";

const WRITE_CMDS = new Set(["all", "insert", "update", "delete"]);

function anonRole(roles: RoleRef[]): string | null {
  for (const r of roles) {
    if (r.roletype === "ROLESPEC_PUBLIC") return "public";
    if (r.roletype === "ROLESPEC_CSTRING" && (r.rolename === "anon" || r.rolename === "public")) {
      return r.rolename;
    }
  }
  return null;
}

// A policy that lets the anonymous (or PUBLIC) role write rows exposes INSERT /
// UPDATE / DELETE to anyone who can reach the API — no session token needed.
export const policyAnonWrite: SchemaRule = (state) =>
  state.policies
    .filter((p) => WRITE_CMDS.has(p.cmd))
    .map((p) => ({ p, role: anonRole(p.roles) }))
    .filter((x): x is { p: typeof x.p; role: string } => x.role !== null)
    .map(({ p, role }) => ({
      ruleId: "POLICY_ANON_WRITE" as const,
      severity: "high" as const,
      file: p.file,
      line: p.line,
      object: p.table,
      evidence: `Policy "${p.name}" grants ${p.cmd.toUpperCase()} to the ${role} role on ${p.table}`,
      remediation:
        `Restrict the policy to an authenticated role (TO authenticated) and bind writes to the ` +
        `caller. The ${role} role is reachable without a session, so this allows anonymous writes.`,
    }));
