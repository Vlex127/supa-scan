// Core types for the scanner. The engine is pure and deterministic: it takes a
// set of already-read files ({path, content}) and returns structured findings.
// It never touches the network, never executes scanned code, and never writes
// to the scanned project. Rule IDs come from a fixed allowlist (no dynamic
// dispatch); a rule is a named function, never a string looked up at runtime.

// `critical` is reserved for a confirmed service_role credential in client-
// reachable code — a full RLS bypass, worse than the SQL misconfigurations.
export type Severity = "critical" | "high" | "medium" | "low" | "info";

// The fixed rule allowlist. SQL rules (1-5) operate on the parsed, ordered
// schema state; source rules (6-7) operate on raw file text and land in slice 3.
// PARSE_FAILED is a diagnostic kind, not a rule: it marks a file the scanner
// could not analyze, so a clean result never silently hides unread input.
export const RULE_IDS = [
  "RLS_DISABLED",
  "POLICY_PERMISSIVE",
  "POLICY_ANON_WRITE",
  "VIEW_NO_SECURITY_INVOKER",
  "SECDEF_NO_SEARCH_PATH",
  "KEY_SERVICE_ROLE_CLIENT",
  "SECRET_COMMITTED",
  "PARSE_FAILED",
] as const;

export type RuleId = (typeof RULE_IDS)[number];

export function isRuleId(value: string): value is RuleId {
  return (RULE_IDS as readonly string[]).includes(value);
}

export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  file: string;
  line: number;
  // The affected database object (table, policy target, view or function) for
  // schema rules. Never echoes a secret value for source rules.
  object?: string;
  // A short, sanitized snippet. For secret-bearing rules the matched value is
  // masked before it ever reaches this field — evidence must never carry a key.
  evidence: string;
  remediation: string;
}

export interface ScannedFile {
  path: string;
  content: string;
}

// A schema rule is a pure function from the final schema state to findings. It
// sees the whole migration set at once because RLS enablement, a policy, or a
// view can be defined in a different file than the table it governs.
export type SchemaRule = (state: SchemaState) => Finding[];

// A text rule is a pure function over the raw content of the files that were read.
// The secret-detection rules (KEY_SERVICE_ROLE_CLIENT, SECRET_COMMITTED) do not
// parse SQL — they pattern-match source and env text — so they take files
// directly and scope themselves (see scope.ts). Like schema rules they are named
// functions, never a string looked up at runtime.
export type TextRule = (files: ScannedFile[]) => Finding[];

export interface TableState {
  qualified: string; // display name, e.g. "public.todos"
  rlsEnabled: boolean;
  file: string;
  line: number;
}

export interface PolicyState {
  name: string;
  table: string; // qualified target table
  cmd: string; // "all" | "select" | "insert" | "update" | "delete"
  roles: RoleRef[];
  usingTrue: boolean;
  withCheckTrue: boolean;
  file: string;
  line: number;
}

// A policy grantee, already resolved to the two things a rule cares about:
// whether it is PUBLIC (everyone) or the anonymous role, plus its name.
export interface RoleRef {
  roletype: string;
  rolename?: string;
}

export interface ViewState {
  qualified: string;
  securityInvoker: boolean;
  file: string;
  line: number;
}

export interface FunctionState {
  qualified: string;
  securityDefiner: boolean;
  setsSearchPath: boolean;
  file: string;
  line: number;
}

export interface SchemaState {
  tables: TableState[];
  policies: PolicyState[];
  views: ViewState[];
  functions: FunctionState[];
}

// A coarse, FIXED classification of why a file failed to parse. We deliberately do
// not carry the parser's own message: Postgres echoes the offending token in errors
// like `unterminated quoted string at or near "'<secret>'"`, so a raw message could
// surface attacker-controlled content (or a credential sitting in the broken SQL).
// A category from this closed allowlist is the only parse-failure detail we emit.
export type ParseErrorCategory =
  | "syntax_error"
  | "unterminated_string"
  | "unterminated_comment"
  | "unterminated_dollar_quote"
  | "invalid_input"
  | "parse_error";

// A file the scanner could not parse. It is reported alongside (never folded
// into) real findings, and forces the scan to be incomplete: the scanner cannot
// certify what it could not read, and an unparsed migration may be exactly the
// one holding the policy we were asked to check.
export interface ParseFailure {
  ruleId: "PARSE_FAILED";
  severity: Severity;
  file: string;
  line: number; // 1-based, derived from the parser's cursor position when available
  category: ParseErrorCategory;
}

// The full result of a scan. `complete` is false when any input was skipped, so
// callers can tell "clean" apart from "could not finish".
export interface ScanResult {
  complete: boolean;
  findings: Finding[];
  parseFailures: ParseFailure[];
}
