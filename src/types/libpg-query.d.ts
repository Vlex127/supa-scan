// Ambient declaration for the one parser surface the scanner uses.
//
// libpg-query ships an index.d.ts but exposes no `types` field and its package
// `main` is a .cjs file, so bundler module resolution cannot reach it. Rather
// than import the ~200-member @pgsql/types union (a transitive dep), we declare
// exactly what we consume and treat the parsed tree as unknown-shaped JSON,
// narrowing it structurally in ./lib/scanner/util.ts.

declare module "libpg-query" {
  export interface ParseResult {
    version: number;
    stmts: unknown[];
  }
  export function parse(query: string): Promise<ParseResult>;
  export function parseSync(query: string): ParseResult;
}
