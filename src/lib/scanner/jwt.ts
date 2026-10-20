// JWT-shaped token detection for the source rules.
//
// We decode a token's payload with the standard Web-API primitives — `atob` for
// base64 and a fatal-mode `TextDecoder` for UTF-8 — both of which exist as globals
// in Node 20+ and in the browser (where the demo UI runs the engine). A fatal
// decoder rejects malformed UTF-8, so bad input degrades to "not decodable" rather
// than a crash or a misleading string. We never verify signatures — that would be
// pointless, and a secret-bearing token is dangerous whatever its signature — we
// only decode the payload to read its `role` claim.

export interface DecodedJwt {
  token: string; // the full token — NEVER surfaced as evidence or reported back
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
}

// Decode one base64url segment (no padding, `-`/`_` alphabet) into a UTF-8 string.
// Returns null on any failure — a bad length, a non-base64 character (atob throws),
// or invalid UTF-8 (the fatal TextDecoder throws) — so a caller treats "undecodable"
// uniformly as "not a token we can read."
function base64urlToUtf8(segment: string): string | null {
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function decodeObject(segment: string): Record<string, unknown> | null {
  const text = base64urlToUtf8(segment);
  if (text === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

// Decode a `header.payload.signature` token into its two JSON objects. Each part
// is independently optional (null when it won't decode); a caller that needs the
// payload role simply checks for a non-null payload.
export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const header = decodeObject(parts[0]);
  const payload = decodeObject(parts[1]);
  if (header === null && payload === null) return null;
  return { token, header, payload };
}

// The Supabase JWT `role` claim maps to the Postgres role the API switches to.
// Only `service_role` is a full RLS bypass; `anon` is the public, logged-out role
// and is never a finding. Anything else (an exotic custom claim, a non-string) is
// reported as itself, masked.
export function isServiceRolePayload(payload: Record<string, unknown> | null): boolean {
  return payload !== null && payload.role === "service_role";
}

export function payloadRole(payload: Record<string, unknown> | null): string | null {
  if (payload === null) return null;
  const role = payload.role;
  return typeof role === "string" ? role : null;
}

// Find JWT-shaped literals in a line whose decoded payload asserts role service_role.
// The token is returned only so its LENGTH can be reported; it is never shown. The
// per-segment `{4,}` keeps the pattern from matching trivial dotted strings (domain
// names, version numbers) that could never be a real three-part token, and a match
// that will not decode to a service_role payload is dropped — so the decode check,
// not the regex, is the real gate. Linear, no nested quantifiers.
export function findServiceRoleJwtLiterals(text: string): string[] {
  const pattern = /(?:[A-Za-z0-9_-]{4,}\.){2}[A-Za-z0-9_-]{4,}/g;
  const out: string[] = [];
  for (const match of text.matchAll(pattern)) {
    const decoded = decodeJwt(match[0]);
    if (decoded !== null && isServiceRolePayload(decoded.payload)) out.push(match[0]);
  }
  return out;
}
