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
