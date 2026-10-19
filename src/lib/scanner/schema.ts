import { parse } from "libpg-query";
import type {
  FunctionState,
  PolicyState,
  RoleRef,
  ScannedFile,
  SchemaState,
  TableState,
  ViewState,
} from "./types";
import {
  fieldArray,
  fieldNumber,
  fieldString,
  isRecord,
  lineFromOffset,
  unwrapNode,
} from "./util";

// Build the FINAL schema state by applying migrations in a deterministic order.
// Supabase migration filenames are timestamp-prefixed, so sorting by path gives
// application order without trusting the caller's array order. RLS is a mutable
// table property (enable here, disable there), so it is replayed in order; the
// other objects are collected as a flat final set.
export async function buildSchema(files: ScannedFile[]): Promise<SchemaState> {
  const sql = files
    .filter((f) => f.path.toLowerCase().endsWith(".sql"))
    .sort((a, b) => a.path.localeCompare(b.path));

  // Keyed by bare relation name so an unqualified `ALTER TABLE todos` matches a
  // `CREATE TABLE public.todos`.
  const tables = new Map<string, TableState>();
  const policies: PolicyState[] = [];
  const views: ViewState[] = [];
  const functions: FunctionState[] = [];

  for (const file of sql) {
    let stmts: unknown[];
    try {
      const result = await parse(file.content);
      stmts = result.stmts ?? [];
    } catch {
      // Unparseable SQL must not abort the scan of the rest of the project.
      continue;
    }
    for (const raw of stmts) {
      if (!isRecord(raw)) continue;
      const stmt = unwrapNode(raw.stmt);
      if (!stmt) continue;
      applyStatement(stmt.kind, stmt.body, file, tables, policies, views, functions);
    }
  }

  return { tables: [...tables.values()], policies, views, functions };
}

function applyStatement(
  kind: string,
  body: Record<string, unknown>,
  file: ScannedFile,
  tables: Map<string, TableState>,
  policies: PolicyState[],
  views: ViewState[],
  functions: FunctionState[],
): void {
  switch (kind) {
    case "CreateStmt": {
      const rel = readRelation(body.relation);
      if (!rel || !rel.exposed) return;
      tables.set(rel.identity, {
        qualified: rel.qualified,
        rlsEnabled: false,
        file: file.path,
        line: lineFromOffset(file.content, rel.location),
      });
      return;
    }
    case "AlterTableStmt": {
      if (fieldString(body, "objtype") !== "OBJECT_TABLE") return;
      const rel = readRelation(body.relation);
      if (!rel) return;
      const state = tables.get(rel.identity);
      if (!state) return; // table is out of scope (non-public) or not created here
      for (const cmd of fieldArray(body, "cmds")) {
        const change = unwrapNode(cmd);
        if (!change || change.kind !== "AlterTableCmd") continue;
        const subtype = fieldString(change.body, "subtype");
        if (subtype === "AT_EnableRowSecurity") state.rlsEnabled = true;
        else if (subtype === "AT_DisableRowSecurity") state.rlsEnabled = false;
      }
      return;
    }
    case "CreatePolicyStmt": {
      const rel = readRelation(body.table);
      if (!rel || !rel.exposed) return;
      policies.push({
        name: fieldString(body, "policy_name") ?? "",
        table: rel.qualified,
        cmd: (fieldString(body, "cmd_name") ?? "all").toLowerCase(),
        roles: readRoles(body.roles),
        usingTrue: isLiteralTrue(body.qual),
        withCheckTrue: isLiteralTrue(body.with_check),
        file: file.path,
        line: lineFromOffset(file.content, rel.location),
      });
      return;
    }
    case "ViewStmt": {
      const rel = readRelation(body.view);
      if (!rel || !rel.exposed) return;
      views.push({
        qualified: rel.qualified,
        securityInvoker: hasSecurityInvoker(body.options),
        file: file.path,
        line: lineFromOffset(file.content, rel.location),
      });
      return;
    }
    case "CreateFunctionStmt": {
      const fn = readFunctionName(body.funcname);
      if (!fn || !fn.exposed) return;
      functions.push({
        qualified: fn.qualified,
        securityDefiner: hasSecurityDefiner(body.options),
        setsSearchPath: hasSetSearchPath(body.options),
        file: file.path,
        line: lineFromOffset(file.content, earliestOptionLocation(body.options)),
      });
      return;
    }
    default:
      return;
  }
}

interface RelationRef {
  qualified: string; // e.g. "public.todos"
  identity: string; // bare lowercased relation name, for alias matching
  exposed: boolean; // public-schema (or unqualified) and not a temp table
  location: number;
}

function readRelation(node: unknown): RelationRef | null {
  const rel = unwrapNode(node);
  const source = rel && rel.kind === "RangeVar" ? rel.body : isRecord(node) ? node : null;
  if (!source) return null;
  const name = fieldString(source, "relname");
  if (!name) return null;
  const schema = fieldString(source, "schemaname");
  const persistence = fieldString(source, "relpersistence");
  const qualified = schema ? `${schema}.${name}` : name;
  const location = fieldNumber(source, "location") ?? 0;
  const exposed = (schema === undefined || schema === "public") && persistence !== "t";
  return { qualified, identity: name.toLowerCase(), exposed, location };
}

function readRoles(nodes: unknown): RoleRef[] {
  const out: RoleRef[] = [];
  for (const item of fieldArray({ roles: nodes }, "roles")) {
    const spec = unwrapNode(item);
    if (!spec || spec.kind !== "RoleSpec") continue;
    out.push({
      roletype: fieldString(spec.body, "roletype") ?? "",
      rolename: fieldString(spec.body, "rolename"),
    });
  }
  return out;
}

// USING (true) / WITH CHECK (true) parse to A_Const { boolval: { boolval: true } }.
function isLiteralTrue(node: unknown): boolean {
  const constNode = unwrapNode(node);
  if (!constNode || constNode.kind !== "A_Const") return false;
  const bool = constNode.body.boolval;
  return isRecord(bool) && bool.boolval === true;
}

function options(nodes: unknown): Record<string, unknown>[] {
  const defs: Record<string, unknown>[] = [];
  for (const item of fieldArray({ options: nodes }, "options")) {
    const def = unwrapNode(item);
    if (def && def.kind === "DefElem") defs.push(def.body);
  }
  return defs;
}

function hasSecurityInvoker(nodes: unknown): boolean {
  for (const def of options(nodes)) {
    if (fieldString(def, "defname") !== "security_invoker") continue;
    // WITH (security_invoker) or (security_invoker=true) is invoker-safe;
    // an explicit false is not.
    const arg = def.arg;
    if (isRecord(arg) && unwrapNode(arg)?.kind === "String") {
      const value = unwrapNode(arg)!.body;
      if (fieldString(value, "sval") === "false") return false;
    }
    return true;
  }
  return false;
}

function hasSecurityDefiner(nodes: unknown): boolean {
  for (const def of options(nodes)) {
    if (fieldString(def, "defname") !== "security") continue;
    const arg = unwrapNode(def.arg);
    return arg?.kind === "Boolean" && arg.body.boolval === true;
  }
  return false;
}

function hasSetSearchPath(nodes: unknown): boolean {
  for (const def of options(nodes)) {
    if (fieldString(def, "defname") !== "set") continue;
    const set = unwrapNode(def.arg);
    if (set?.kind === "VariableSetStmt" && fieldString(set.body, "name") === "search_path") {
      return true;
    }
  }
  return false;
}

interface FunctionRef {
  qualified: string;
  exposed: boolean;
}

// funcname is a list of String nodes: [schema, name] or [name].
function readFunctionName(nodes: unknown): FunctionRef | null {
  const parts: string[] = [];
  for (const item of fieldArray({ funcname: nodes }, "funcname")) {
    const str = unwrapNode(item);
    if (str?.kind === "String") {
      const value = fieldString(str.body, "sval");
      if (value) parts.push(value);
    }
  }
  if (parts.length === 0) return null;
  const name = parts[parts.length - 1];
  const schema = parts.length > 1 ? parts[parts.length - 2] : undefined;
  return {
    qualified: schema ? `${schema}.${name}` : name,
    exposed: schema === undefined || schema === "public",
  };
}

function earliestOptionLocation(nodes: unknown): number {
  let min = Number.POSITIVE_INFINITY;
  for (const item of fieldArray({ options: nodes }, "options")) {
    const def = unwrapNode(item);
    const loc = def ? fieldNumber(def.body, "location") : undefined;
    if (loc !== undefined && loc < min) min = loc;
  }
  return Number.isFinite(min) ? min : 0;
}
