// Test-only builders for credential-shaped strings. Nothing that looks like a real
// secret is committed to the repo: tokens are assembled at test time (base64url of
// an in-memory object, random bodies) and written only into throwaway temp dirs.
import { randomBytes } from "node:crypto";

// base64url WITHOUT padding, matching how a JWT segment is encoded. Node's Buffer
// supports the alphabet directly; this is test scaffolding, not shipped code.
export function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

export function makeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const sig = randomBytes(16).toString("base64url");
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.${sig}`;
}

const HEADER = { alg: "HS256", typ: "JWT" };

export function serviceRoleJwtPayload(): Record<string, unknown> {
  // A unique nonce so the payload's base64url is a value we can assert is absent
  // from every output path — proving the engine masked it, not just truncated it.
  return { role: "service_role", iss: "supabase", nonce: randomBytes(12).toString("hex") };
}

export function serviceRoleJwt(): string {
  return makeJwt(HEADER, serviceRoleJwtPayload());
}

export function anonJwt(): string {
  return makeJwt(HEADER, { role: "anon", iss: "supabase" });
}

export function authenticatedJwt(): string {
  return makeJwt(HEADER, { role: "authenticated", iss: "supabase" });
}

export function supabaseSecretKey(): string {
  return `sb_secret_${randomBytes(20).toString("base64url")}`;
}

export function supabasePublishableKey(): string {
  return `sb_publishable_${randomBytes(16).toString("base64url")}`;
}

export function personalAccessToken(): string {
  return `sbp_${randomBytes(20).toString("base64url")}`;
}

// The base64url of a service_role payload's JSON, given its payload object — used
// by leak assertions to confirm that exact substring never reaches an output.
export function payloadSegment(payload: Record<string, unknown>): string {
  return b64url(JSON.stringify(payload));
}
