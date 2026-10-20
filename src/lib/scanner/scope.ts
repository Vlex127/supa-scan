// Central file-scope decisions, shared by the CLI collector (what to read / what
// counts as a dropped-but-scannable input) and the source rules (what to scan).
// Keeping one source of truth means the "skipped means incomplete" signal and the
// rules' own scoping can never drift apart.

const SQL_EXT = ".sql";

// Source and config files the secret rules may inspect. Narrow on purpose: real
// application and config text, never generated or vendored data.
const SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
]);

// Env files are `.env`, `.env.local`, `.env.production`, etc. Never `.env.example`
// and friends (see isVendoredFile) — those are templates meant to hold placeholders.
const ENV_BASENAME_RE = /^\.env(\..+)?$/;
const ENV_TEMPLATE_RE =
  /(^|\/)\.env\.(?:template|sample|example|dist|default|example\.local|sample\.local)$/;

// Files that are never our code: vendored dependencies, generated lockfiles,
// minified / source-map output, and secret templates. Excluded entirely — not read
// as scannable, so skipping one never marks a scan incomplete.
const VENDOR_DIR_RE = /(^|\/)(node_modules|vendor|third_party)(\/|$)/;
const LOCKFILE_RE =
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|deno\.lock\.json|flake\.lock)$/;
const MINIFIED_RE = /\.min\.(?:js|mjs|cjs|css)$/;
const SOURCEMAP_RE = /\.map$/;

function extname(path: string): string {
  const slash = path.lastIndexOf("/");
  const name = slash >= 0 ? path.slice(slash + 1) : path;
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot).toLowerCase() : "";
}

function basename(path: string): string {
  const slash = path.lastIndexOf("/");
  return slash >= 0 ? path.slice(slash + 1) : path;
}

export function isSqlFile(path: string): boolean {
  return extname(path) === SQL_EXT;
}

export function isSourceFile(path: string): boolean {
  return SOURCE_EXTENSIONS.has(extname(path));
}

export function isEnvFile(path: string): boolean {
  return ENV_BASENAME_RE.test(basename(path)) && !isVendoredFile(path);
}

export function isScannable(path: string): boolean {
  return isSqlFile(path) || isSourceFile(path) || isEnvFile(path);
}

export function isVendoredFile(path: string): boolean {
  const p = path.toLowerCase();
  if (VENDOR_DIR_RE.test(p)) return true;
  if (LOCKFILE_RE.test(p)) return true;
  if (MINIFIED_RE.test(p)) return true;
  if (SOURCEMAP_RE.test(p)) return true;
  if (ENV_TEMPLATE_RE.test(p)) return true;
  return false;
}
