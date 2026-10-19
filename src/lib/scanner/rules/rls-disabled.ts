import type { SchemaRule } from "../types";

// A public, non-temp table that never gets ROW LEVEL SECURITY enabled is fully
// readable and writable by the anon/authenticated roles through PostgREST.
export const rlsDisabled: SchemaRule = (state) =>
  state.tables
    .filter((t) => !t.rlsEnabled)
    .map((t) => ({
      ruleId: "RLS_DISABLED" as const,
      severity: "high" as const,
      file: t.file,
      line: t.line,
      object: t.qualified,
      evidence: `Table ${t.qualified} is created without ROW LEVEL SECURITY enabled`,
      remediation:
        `ALTER TABLE ${t.qualified} ENABLE ROW LEVEL SECURITY; then add least-privilege policies. ` +
        "Without RLS, the anon and authenticated roles can read and write every row via the API.",
    }));
