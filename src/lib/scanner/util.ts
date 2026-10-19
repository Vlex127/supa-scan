// Structural readers for the libpg-query AST plus line-number helpers.
//
// We deliberately do NOT import the concrete @pgsql/types node interfaces. That
// package is a transitive dependency of libpg-query, and its `Node` type is a
// ~200-member union; coupling our rules to it would be brittle across parser
// upgrades. Instead the parser's output is treated as untrusted-shaped JSON and
// narrowed here. If a node is missing or has an unexpected type, readers return
// undefined and the rule simply declines to fire — a missed finding must never
// become a crash on hostile input.

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export interface ParsedNode {
  kind: string;
  body: Record<string, unknown>;
}

// libpg-query wraps every AST node as a single-key object, e.g.
// { CreateStmt: { ... } }. Unwrap that one key; anything else is not a node.
export function unwrapNode(node: unknown): ParsedNode | null {
  if (!isRecord(node)) return null;
  const keys = Object.keys(node);
  if (keys.length !== 1) return null;
  const body = node[keys[0]];
  if (!isRecord(body)) return null;
  return { kind: keys[0], body };
}

export function fieldString(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  return typeof value === "string" ? value : undefined;
}

export function fieldNumber(body: Record<string, unknown>, key: string): number | undefined {
  const value = body[key];
  return typeof value === "number" ? value : undefined;
}

export function fieldArray(body: Record<string, unknown>, key: string): unknown[] {
  const value = body[key];
  return Array.isArray(value) ? value : [];
}

// Read a list of { String: { sval } } nodes into their string values, in order.
// Used for qualified-name paths (DROP targets, function names).
export function stringNodes(items: unknown): string[] {
  const out: string[] = [];
  if (!Array.isArray(items)) return out;
  for (const item of items) {
    const node = unwrapNode(item);
    if (node?.kind === "String") {
      const value = fieldString(node.body, "sval");
      if (value !== undefined) out.push(value);
    }
  }
  return out;
}

// Last segment of a dotted name; the parser normalizes identifiers, so this is
// a stable identity across `todos` and `public.todos`.
export function lastSegment(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot === -1 ? name : name.slice(dot + 1);
}

// The set of roles that can be reached without a signed-in session: the `anon`
// role and the PUBLIC pseudo-role. `authenticated` is excluded on purpose — it
// requires a valid JWT and its privileges are governed by RLS policies, so a
// policy bound only to it is not anonymous access.
export function hasWriteRole(roles: { roletype: string; rolename?: string }[]): boolean {
  return roles.some(
    (r) =>
      r.roletype === "ROLESPEC_PUBLIC" ||
      (r.roletype === "ROLESPEC_CSTRING" && r.rolename === "anon"),
  );
}

// Convert an absolute byte offset (a node's `location`) into a 1-based line
// number within the file content the offset indexes.
export function lineFromOffset(content: string, offset: number): number {
  if (!Number.isFinite(offset) || offset < 0) return 1;
  const limit = Math.min(offset, content.length);
  let line = 1;
  for (let i = 0; i < limit; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}
