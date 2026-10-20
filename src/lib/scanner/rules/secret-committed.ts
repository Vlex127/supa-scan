import type { Finding, ScannedFile, TextRule } from "../types";
import { isSourceFile, isEnvFile } from "../scope";
import { scanLines, clipName, describeLength } from "../masking";
import { findServiceRoleJwtLiterals } from "../jwt";

// A narrow, Supabase-specific committed-secret check. General secret scanning is
// gitleaks' job; this rule exists because a Supabase scanner should catch Supabase's
// OWN credential formats. It fires on:
//   * an sb_secret_* or sbp_* (personal-access-token) key — anywhere;
//   * a PEM private-key block — anywhere;
//   * a service_role JWT sitting in a .env file — in SOURCE files that signal is
//     owned by KEY_SERVICE_ROLE_CLIENT (critical), so we only take the env case here
//     to avoid double-reporting the same token;
//   * a key-like NAME assigned a non-empty value in a .env file.
// Evidence never shows the value: the matched format and a length are enough.

const SB_SECRET_RE = /sb_secret_[A-Za-z0-9_-]{10,}/g;
const SBP_RE = /sbp_[A-Za-z0-9_-]{10,}/g;
const PEM_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const ENV_ASSIGN_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

const REMEDIATION =
  "Remove this credential from version control and rotate it — treat it as compromised " +
  "the moment it was committed. Load secrets from the deployment environment instead, and " +
  "let a dedicated tool like gitleaks (or GitHub push protection) cover general secrets.";

function looksLikeSecretName(name: string): boolean {
  const upper = name.toUpperCase();
  if (/SERVICE_ROLE|SECRET|PRIVATE_KEY|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY/.test(upper)) {
    return true;
  }
  return upper.endsWith("_KEY");
}

// A placeholder or empty assignment is not a leak. Dequote a single surrounding pair,
// ignore comment-only or blank values, and require a real minimum length so `KEY=` or
// `KEY=""` does not fire.
function valueLooksPresent(value: string): boolean {
  let v = value.trim();
  if (v === "" || v.startsWith("#")) return false;
  const quote = v[0];
  if ((quote === '"' || quote === "'") && v.length >= 2 && v.endsWith(quote)) {
    v = v.slice(1, -1).trim();
  }
  if (v === "") return false;
  return v.length >= 6;
}

function pushSecret(
  findings: Finding[],
  file: ScannedFile,
  line: number,
  evidence: string,
  object?: string,
): void {
  findings.push({
    ruleId: "SECRET_COMMITTED",
    severity: "high",
    file: file.path,
    line,
    ...(object !== undefined ? { object } : {}),
    evidence,
    remediation: REMEDIATION,
  });
}

export const secretCommitted: TextRule = (files: ScannedFile[]): Finding[] => {
  const findings: Finding[] = [];

  for (const file of files) {
    const env = isEnvFile(file.path);
    if (!env && !isSourceFile(file.path)) continue;

    for (const { line, text, skipped } of scanLines(file.content)) {
      if (skipped) continue;

      let formatHit = false;

      for (const match of text.matchAll(SB_SECRET_RE)) {
        pushSecret(
          findings,
          file,
          line,
          `A Supabase secret key (${clipName(match[0].slice(0, 10))}…, ${describeLength(match[0])}) appears in ${file.path}.`,
        );
        formatHit = true;
      }
      for (const match of text.matchAll(SBP_RE)) {
        pushSecret(
          findings,
          file,
          line,
          `A Supabase access token (${clipName(match[0].slice(0, 4))}…, ${describeLength(match[0])}) appears in ${file.path}.`,
        );
        formatHit = true;
      }

      const pem = text.match(PEM_RE);
      if (pem !== null) {
        pushSecret(
          findings,
          file,
          line,
          `A PEM private key block begins here (${clipName(pem[0])}) in ${file.path}.`,
        );
        formatHit = true;
      }

      if (env) {
        // A service_role JWT committed in a .env file (the source-file case is KEY's).
        for (const token of findServiceRoleJwtLiterals(text)) {
          pushSecret(
            findings,
            file,
            line,
            `A JWT asserting role "service_role" (${describeLength(token)}) is committed in ${file.path}.`,
          );
          formatHit = true;
        }

        // A secret-shaped variable NAME with a real value in a .env file. Skipped when
        // a stronger format match already reported this exact line.
        if (!formatHit) {
          const assign = text.match(ENV_ASSIGN_RE);
          if (assign !== null && looksLikeSecretName(assign[1]) && valueLooksPresent(assign[2])) {
            pushSecret(
              findings,
              file,
              line,
              `Environment variable "${clipName(assign[1])}" is assigned a ${describeLength(assign[2].trim())} value that looks like a secret.`,
              clipName(assign[1]),
            );
          }
        }
      }
    }
  }

  return dedupe(findings);
};

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
