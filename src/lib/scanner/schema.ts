import { parse } from "libpg-query";
import type {
  FunctionState,
  ParseErrorCategory,
  ParseFailure,
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
  lastSegment,
  lineFromOffset,
  stringNodes,
  unwrapNode,
} from "./util";

export interface SchemaBuild {
  state: SchemaState;
  parseFailures: ParseFailure[];
}

// Build the FINAL schema state by applying migrations in a deterministic order.
// Supabase migration filenames are timestamp-prefixed, so sorting by path gives
// application order without trusting the caller's array order. Tables, views and
// functions are keyed maps so a later CREATE OR REPLACE or ALTER overwrites the
// earlier definition; DROP removes them. A file that fails to parse is recorded
// as a parse failure and contributes nothing — the scan is then incomplete.
export async function buildSchema(files: ScannedFile[]): Promise<SchemaBuild> {
  const sql = files
    .filter((f) => f.path.toLowerCase().endsWith(".sql"))
    .sort((a, b) => a.path.localeCompare(b.path));

  const ctx: Ctx = {
    tables: new Map(),
    views: new Map(),
    functions: new Map(),
    policies: [],
  };
  const parseFailures: ParseFailure[] = [];

  for (const file of sql) {
    let stmts: unknown[];
    try {
      const result = await parse(file.content);
      stmts = Array.isArray(result.stmts) ? result.stmts : [];
    } catch (error) {
      parseFailures.push({
        ruleId: "PARSE_FAILED",
        severity: "high",
        file: file.path,
        line: parseErrorLine(file.content, error),
        category: parseErrorCategory(error),
      });
      continue;
    }
    for (const raw of stmts) {
      if (!isRecord(raw)) continue;
      const stmt = unwrapNode(raw.stmt);
      if (!stmt) continue;
      applyStatement(ctx, stmt.kind, stmt.body, file);
    }
  }

  return {
    state: {
      tables: [...ctx.tables.values()],
      views: [...ctx.views.values()],
      functions: [...ctx.functions.values()],
      policies: ctx.policies,
    },
    parseFailures,
  };
}

// libpg-query throws a SqlError whose `sqlDetails` carries the original parser
// message and an absolute `cursorPosition` into the input. We use those two — and
// nothing else — to place and classify the failure. The message itself is never
// stored: Postgres interpolates the offending token (e.g. an unterminated quoted
// string echoes its contents), so surfacing it could leak attacker-controlled text
// or a credential sitting inside the broken SQL. We map it onto a closed category.
function parserMessage(error: unknown): string {
  if (error && typeof error === "object") {
    const details = (error as { sqlDetails?: { message?: unknown } }).sqlDetails;
    if (typeof details?.message === "string") return details.message;
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  return "";
}

function parseErrorLine(content: string, error: unknown): number {
  if (!error || typeof error !== "object") return 1;
  const cursor = (error as { sqlDetails?: { cursorPosition?: unknown } }).sqlDetails
    ?.cursorPosition;
  return typeof cursor === "number" ? lineFromOffset(content, cursor) : 1;
}

function parseErrorCategory(error: unknown): ParseErrorCategory {
  const message = parserMessage(error);
  if (message.startsWith("syntax error")) return "syntax_error";
  if (message.startsWith("unterminated dollar-quoted string")) return "unterminated_dollar_quote";
  if (message.startsWith("unterminated quoted string")) return "unterminated_string";
  if (message.startsWith("unterminated /* comment")) return "unterminated_comment";
  if (message.startsWith("invalid input syntax")) return "invalid_input";
  return "parse_error";
}

interface Ctx {
  tables: Map<string, TableState>;
  views: Map<string, ViewState>;
  functions: Map<string, FunctionState>;
  policies: PolicyState[];
}

function applyStatement(
  ctx: Ctx,
  kind: string,
  body: Record<string, unknown>,
  file: ScannedFile,
): void {
  switch (kind) {
    case "CreateStmt": {
      const rel = readRelation(body.relation);
      if (!rel || !rel.exposed) return;
      ctx.tables.set(rel.identity, {
        qualified: rel.qualified,
        rlsEnabled: false,
        file: file.path,
        line: lineFromOffset(file.content, rel.location),
      });
      return;
    }
    case "AlterTableStmt": {
      const rel = readRelation(body.relation);
      if (!rel) return;
      const objtype = fieldString(body, "objtype");
      if (objtype === "OBJECT_TABLE") {
        const table = ctx.tables.get(rel.identity);
        if (!table) return;
        for (const change of alterCmds(body)) {
          const subtype = fieldString(change, "subtype");
          if (subtype === "AT_EnableRowSecurity") table.rlsEnabled = true;
          else if (subtype === "AT_DisableRowSecurity") table.rlsEnabled = false;
          // FORCE / NO FORCE change table-owner bypass, not whether RLS is on;
          // they leave rlsEnabled as-is.
        }
      } else if (objtype === "OBJECT_VIEW") {
        const view = ctx.views.get(rel.identity);
        if (!view) return;
        for (const change of alterCmds(body)) {
          const subtype = fieldString(change, "subtype");
          if (subtype !== "AT_SetRelOptions" && subtype !== "AT_ResetRelOptions") continue;
          for (const def of defElems(fieldValue(change, "def"))) {
            if (fieldString(def, "defname") !== "security_invoker") continue;
            view.securityInvoker =
              subtype === "AT_SetRelOptions" && stringValue(fieldValue(def, "arg")) !== "false";
          }
        }
      }
      return;
    }
    case "CreatePolicyStmt": {
      const rel = readRelation(body.table);
      if (!rel || !rel.exposed) return;
      ctx.policies.push({
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
    case "AlterPolicyStmt": {
      const rel = readRelation(body.table);
      if (!rel) return;
      const name = fieldString(body, "policy_name") ?? "";
      const policy = ctx.policies.find(
        (p) => p.name === name && lastSegment(p.table) === rel.identity,
      );
      if (!policy) return;
      const roles = body.roles;
      if (roles !== undefined) policy.roles = readRoles(roles);
      if (body.qual !== undefined) policy.usingTrue = isLiteralTrue(body.qual);
      if (body.with_check !== undefined) policy.withCheckTrue = isLiteralTrue(body.with_check);
      return;
    }
    case "DropStmt":
      applyDrop(ctx, body);
      return;
    case "ViewStmt": {
      const rel = readRelation(body.view);
      if (!rel || !rel.exposed) return;
      ctx.views.set(rel.identity, {
        qualified: rel.qualified,
        securityInvoker: hasSecurityInvoker(body.options),
        file: file.path,
        line: lineFromOffset(file.content, rel.location),
      });
      return;
    }
    case "CreateFunctionStmt": {
      const fn = readNameList(body.funcname);
      if (!fn || !fn.exposed) return;
      ctx.functions.set(fn.identity, {
        qualified: fn.qualified,
        securityDefiner: hasSecurityDefiner(body.options),
        setsSearchPath: hasSetSearchPath(body.options),
        file: file.path,
        line: lineFromOffset(file.content, earliestOptionLocation(body.options)),
      });
      return;
    }
    case "AlterFunctionStmt": {
      if (fieldString(body, "objtype") !== "OBJECT_FUNCTION") return;
      const func = isRecord(body.func) ? body.func : undefined;
      const fn = func ? readNameList(fieldValue(func, "objname")) : null;
      if (!fn) return;
      const target = ctx.functions.get(fn.identity);
      if (!target) return;
      for (const def of defElems(body.actions)) {
        const defname = fieldString(def, "defname");
        if (defname === "set") {
          const set = unwrapNode(fieldValue(def, "arg"));
          if (set?.kind === "VariableSetStmt" && fieldString(set.body, "name") === "search_path") {
            target.setsSearchPath = true;
          }
        } else if (defname === "security") {
          const value = unwrapNode(fieldValue(def, "arg"));
          if (value?.kind === "Boolean") target.securityDefiner = value.body.boolval === true;
        }
      }
      return;
    }
    default:
      return;
  }
}

function applyDrop(ctx: Ctx, body: Record<string, unknown>): void {
  const removeType = fieldString(body, "removeType");
  for (const object of fieldArray(body, "objects")) {
    const list = unwrapNode(object);
    if (!list || list.kind !== "List") continue;
    const path = stringNodes(fieldArray(list.body, "items"));
    if (path.length === 0) continue;
    const name = path[path.length - 1];
    if (removeType === "OBJECT_TABLE") ctx.tables.delete(name);
    else if (removeType === "OBJECT_VIEW") ctx.views.delete(name);
    else if (removeType === "OBJECT_FUNCTION") ctx.functions.delete(name);
    else if (removeType === "OBJECT_POLICY" && path.length >= 2) {
      const tableName = path[path.length - 2];
      ctx.policies = ctx.policies.filter(
        (p) => !(p.name === name && lastSegment(p.table) === tableName),
      );
    }
  }
}

// Reused helpers -------------------------------------------------------------

interface RelationRef {
  qualified: string;
  identity: string; // parser-normalized relation name (case already folded)
  exposed: boolean;
  location: number;
}

function readRelation(node: unknown): RelationRef | null {
  const wrapped = unwrapNode(node);
  const source = wrapped && wrapped.kind === "RangeVar" ? wrapped.body : isRecord(node) ? node : null;
  if (!source) return null;
  const name = fieldString(source, "relname");
  if (!name) return null;
  const schema = fieldString(source, "schemaname");
  const persistence = fieldString(source, "relpersistence");
  return {
    qualified: schema ? `${schema}.${name}` : name,
    identity: name,
    exposed: (schema === undefined || schema === "public") && persistence !== "t",
    location: fieldNumber(source, "location") ?? 0,
  };
}

interface NameRef {
  qualified: string;
  identity: string;
  exposed: boolean;
}

// Read a dotted name from a list of { String } nodes: [schema, name] or [name].
function readNameList(nodes: unknown): NameRef | null {
  const parts = Array.isArray(nodes) ? stringNodes(nodes) : [];
  if (parts.length === 0) return null;
  const name = parts[parts.length - 1];
  const schema = parts.length > 1 ? parts[parts.length - 2] : undefined;
  return {
    qualified: schema ? `${schema}.${name}` : name,
    identity: name,
    exposed: schema === undefined || schema === "public",
  };
}

function fieldValue(node: Record<string, unknown>, key: string): unknown {
  return node[key];
}

function stringValue(node: unknown): string | undefined {
  const wrapped = unwrapNode(node);
  if (wrapped?.kind === "String") return fieldString(wrapped.body, "sval");
  return undefined;
}

function alterCmds(body: Record<string, unknown>): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const item of fieldArray(body, "cmds")) {
    const cmd = unwrapNode(item);
    if (cmd?.kind === "AlterTableCmd") out.push(cmd.body);
  }
  return out;
}

// defElems accepts either a raw array of { DefElem } nodes (function options,
// actions) or a single { List: { items } } wrapper (a rel-option `def`).
function defElems(nodes: unknown): Record<string, unknown>[] {
  const list: unknown[] = Array.isArray(nodes)
    ? nodes
    : (() => {
        const wrapped = unwrapNode(nodes);
        return wrapped?.kind === "List" ? fieldArray(wrapped.body, "items") : [];
      })();
  const out: Record<string, unknown>[] = [];
  for (const item of list) {
    const def = unwrapNode(item);
    if (def?.kind === "DefElem") out.push(def.body);
  }
  return out;
}

function readRoles(nodes: unknown): RoleRef[] {
  const out: RoleRef[] = [];
  for (const item of Array.isArray(nodes) ? nodes : []) {
    const spec = unwrapNode(item);
    if (!spec || spec.kind !== "RoleSpec") continue;
    out.push({
      roletype: fieldString(spec.body, "roletype") ?? "",
      rolename: fieldString(spec.body, "rolename"),
    });
  }
  return out;
}

function isLiteralTrue(node: unknown): boolean {
  const constNode = unwrapNode(node);
  if (!constNode || constNode.kind !== "A_Const") return false;
  const bool = constNode.body.boolval;
  return isRecord(bool) && bool.boolval === true;
}

function hasSecurityInvoker(nodes: unknown): boolean {
  for (const def of defElems(nodes)) {
    if (fieldString(def, "defname") !== "security_invoker") continue;
    return stringValue(fieldValue(def, "arg")) !== "false";
  }
  return false;
}

function hasSecurityDefiner(nodes: unknown): boolean {
  for (const def of defElems(nodes)) {
    if (fieldString(def, "defname") !== "security") continue;
    const arg = unwrapNode(fieldValue(def, "arg"));
    return arg?.kind === "Boolean" && arg.body.boolval === true;
  }
  return false;
}

function hasSetSearchPath(nodes: unknown): boolean {
  for (const def of defElems(nodes)) {
    if (fieldString(def, "defname") !== "set") continue;
    const set = unwrapNode(fieldValue(def, "arg"));
    if (set?.kind === "VariableSetStmt" && fieldString(set.body, "name") === "search_path") {
      return true;
    }
  }
  return false;
}

function earliestOptionLocation(nodes: unknown): number {
  let min = Number.POSITIVE_INFINITY;
  for (const def of defElems(nodes)) {
    const loc = fieldNumber(def, "location");
    if (loc !== undefined && loc < min) min = loc;
  }
  return Number.isFinite(min) ? min : 0;
}
