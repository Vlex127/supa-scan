// JWT-shaped token detection for the source rules.
//
// We deliberately avoid `Buffer` and the global `TextDecoder`: the scanner engine
// must stay runnable in a browser (the demo UI runs it client-side), and base64url
// decoding plus UTF-8 decoding are only a few dozen lines. We never verify
// signatures — that would be pointless, and a secret-bearing token is dangerous
// whatever its signature — we only decode the payload to read its `role` claim.

export interface DecodedJwt {
  token: string; // the full token — NEVER surfaced as evidence or reported back
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
}

// RFC 7515/7519 base64url alphabet, encoded as a value array so an invalid byte
// reads as 0xFF (below) instead of the value 0 it would get from a missing key.
const B64 = new Uint8Array(256).fill(0xff);
{
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  for (let i = 0; i < ALPHABET.length; i++) {
    B64[ALPHABET.charCodeAt(i)] = i;
  }
}

function base64urlToBytes(input: string): Uint8Array | null {
  let bitBuffer = 0;
  let bitCount = 0;
  const out: number[] = [];
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    const value = code < B64.length ? B64[code] : 0xff;
    if (value === 0xff) {
      // '=' padding is legal at the tail of some tokens; anything else is invalid.
      if (code === 0x3d /* = */) continue;
      return null;
    }
    bitBuffer = (bitBuffer << 6) | value;
    bitCount += 6;
    if (bitCount >= 8) {
      bitCount -= 8;
      out.push((bitBuffer >> bitCount) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// Minimal, strict-enough UTF-8 decoder. Malformed or truncated sequences yield
// U+FFFD, which JSON.parse then rejects — so bad input degrades to "not decodable"
// rather than a crash or a misleading string.
function utf8Decode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i];
    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
      i += 1;
      continue;
    }
    if (b0 >= 0xc2 && b0 <= 0xdf && i + 1 < bytes.length) {
      const b1 = bytes[i + 1];
      if ((b1 & 0xc0) === 0x80) {
        out += String.fromCharCode(((b0 & 0x1f) << 6) | (b1 & 0x3f));
        i += 2;
        continue;
      }
    } else if (b0 >= 0xe0 && b0 <= 0xef && i + 2 < bytes.length) {
      const b1 = bytes[i + 1];
      const b2 = bytes[i + 2];
      if ((b1 & 0xc0) === 0x80 && (b2 & 0xc0) === 0x80) {
        out += String.fromCharCode(((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f));
        i += 3;
        continue;
      }
    } else if (b0 >= 0xf0 && b0 <= 0xf4 && i + 3 < bytes.length) {
      const b1 = bytes[i + 1];
      const b2 = bytes[i + 2];
      const b3 = bytes[i + 3];
      if ((b1 & 0xc0) === 0x80 && (b2 & 0xc0) === 0x80 && (b3 & 0xc0) === 0x80) {
        const cp =
          ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
        out += String.fromCodePoint(cp);
        i += 4;
        continue;
      }
    }
    out += "\uFFFD"; // replacement character for a malformed sequence
    i += 1;
  }
  return out;
}

function decodeObject(segment: string): Record<string, unknown> | null {
  const bytes = base64urlToBytes(segment);
  if (bytes === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(bytes));
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
