import type { Finding, ScannedFile, TextRule } from "../types";
import { isSourceFile } from "../scope";
import { scanChunks, clipName, describeLength } from "../masking";
import { findServiceRoleJwtLiterals } from "../jwt";

// The service_role key (and its sb_secret_/sbp_ successors) bypasses row-level
// security entirely, so it must never reach a browser or mobile bundle. Three
// independent ways it leaks into client-reachable code, all scoped to SOURCE files:
//
//   (a) a NEXT_PUBLIC_* variable whose NAME mentions SERVICE_ROLE or SECRET — Next
//       inlines any NEXT_PUBLIC_* value into the client bundle, so the name alone is
//       the leak, whatever the value is (high);
//   (b) a service-role reference in a file that declares "use client" (high);
//   (c) a JWT literal whose decoded payload asserts role: service_role (critical).
//
// `anon` is never flagged — it is the public, logged-out role and is meant to ship.

const NEXT_PUBLIC_RE = /NEXT_PUBLIC_[A-Z0-9_]*/g;
const SERVICE_ROLE_REF_RE = /service_role|serviceRole|SERVICE_ROLE|SUPABASE_SERVICE|sb_secret_/;

const REMEDIATION_A =
  "Never expose a service-role secret through a NEXT_PUBLIC_ variable. Keep it in a " +
  "server-only env var and call Supabase from a server route or edge function.";
const REMEDIATION_B =
  "Remove the service-role credential from client code. A 'use client' module ships to " +
  "the browser; obtain a user-scoped anon key instead and let row-level security govern access.";
const REMEDIATION_C =
  "Revoke and rotate this service_role key immediately (it is a full RLS bypass) and remove " +
  "it from client code. Issue short-lived user tokens with the anon role instead.";

// A match must begin a token, not sit inside a longer identifier (e.g. the middle
// of VITE_NEXT_PUBLIC_FOO). We check the character before the match explicitly so
// a NEXT_PUBLIC_ name at column 0 still counts.
function isIdentifierChar(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) || // 0-9
    (code >= 0x41 && code <= 0x5a) || // A-Z
    (code >= 0x61 && code <= 0x7a) || // a-z
    code === 0x5f // _
  );
}

function nextPublicSecretNameAt(text: string, index: number, name: string): boolean {
  if (index > 0 && isIdentifierChar(text.charCodeAt(index - 1))) return false;
  return name.includes("SERVICE_ROLE") || name.includes("SECRET");
}

// The first meaningful line of a module: the "use client" directive must be the
// leading statement (after blank/slash lines). A leading /* block */ is unusual
// here and treated approximately — the directive is normally line 1.
function usesClientDirective(content: string): boolean {
  for (const raw of content.split("\n")) {
    const trimmed = raw.trim();
    if (trimmed === "" || trimmed.startsWith("//")) continue;
    return /^['"]use client['"]/.test(trimmed);
  }
  return false;
}

export const keyServiceRoleClient: TextRule = (files: ScannedFile[]): Finding[] => {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!isSourceFile(file.path)) continue;
    const useClient = usesClientDirective(file.content);

    for (const { line, text } of scanChunks(file.content)) {
      // (c) A decoded service_role JWT is the most severe signal; it is a literal
      // credential regardless of any name or directive.
      for (const token of findServiceRoleJwtLiterals(text)) {
        findings.push({
          ruleId: "KEY_SERVICE_ROLE_CLIENT",
          severity: "critical",
          file: file.path,
          line,
          evidence: `A JWT asserting role "service_role" (${describeLength(token)}) appears in ${file.path}.`,
          remediation: REMEDIATION_C,
        });
      }

      // (a) NEXT_PUBLIC_* name leak — value-independent, so it also applies inside
      // server files; the name is enough to know a secret is being shipped.
      for (const match of text.matchAll(NEXT_PUBLIC_RE)) {
        const start = match.index ?? 0;
        const name = match[0];
        if (nextPublicSecretNameAt(text, start, name)) {
          findings.push({
            ruleId: "KEY_SERVICE_ROLE_CLIENT",
            severity: "high",
            file: file.path,
            line,
            object: clipName(name),
            evidence: `NEXT_PUBLIC_ variable "${clipName(name)}" names a service-role/secret value; Next inlines every NEXT_PUBLIC_* value into the client bundle.`,
            remediation: REMEDIATION_A,
          });
        }
      }

      // (b) A textual service-role reference is only a client leak when the module
      // is marked for the client. (The sb_secret_ value itself is covered by the
      // SECRET_COMMITTED rule; this case is about a reference inside client code.)
      if (useClient) {
        const ref = text.match(SERVICE_ROLE_REF_RE);
        if (ref !== null) {
          findings.push({
            ruleId: "KEY_SERVICE_ROLE_CLIENT",
            severity: "high",
            file: file.path,
            line,
            evidence: `A "use client" module references a service-role credential ("${clipName(ref[0])}") — this code ships to the browser.`,
            remediation: REMEDIATION_B,
          });
        }
      }
    }
  }
  return dedupe(findings);
};

// A single line can match more than one shape; collapse exact repeats (same line,
// same object) while keeping genuinely distinct signals.
function dedupe(input: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of input) {
    const key = `${f.file}:${f.line}:${f.ruleId}:${f.object ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
