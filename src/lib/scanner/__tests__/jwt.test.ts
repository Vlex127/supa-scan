import { describe, expect, it } from "vitest";
import {
  decodeJwt,
  findServiceRoleJwtLiterals,
  isServiceRolePayload,
  payloadRole,
} from "../jwt";
import {
  anonJwt,
  authenticatedJwt,
  payloadSegment,
  serviceRoleJwt,
  serviceRoleJwtPayload,
} from "../../../../tests/helpers/build-token";

describe("decodeJwt", () => {
  it("returns null for a token whose parts are not base64url JSON", () => {
    expect(decodeJwt("x.y.z")).toBeNull();
    expect(decodeJwt("a.b")).toBeNull(); // only two parts is not a JWT
  });

  it("round-trips a runtime-built service_role JWT", () => {
    const token = serviceRoleJwt();
    const decoded = decodeJwt(token);
    expect(decoded).not.toBeNull();
    expect(decoded?.header).toMatchObject({ alg: "HS256", typ: "JWT" });
    expect(decoded?.payload?.role).toBe("service_role");
  });

  it("returns null when no part decodes to an object", () => {
    expect(decodeJwt("not.a.jwt")).toBeNull();
    expect(decodeJwt("1.2.3")).toBeNull();
    expect(decodeJwt("www.example.com")).toBeNull();
  });

  it("decodes a payload even if the header is not JSON", () => {
    // signature and header are irrelevant to the role check.
    const token = serviceRoleJwt();
    const [, p] = token.split(".");
    const scrambled = `zzzz.${p}.nope`;
    const decoded = decodeJwt(scrambled);
    expect(decoded?.payload?.role).toBe("service_role");
  });
});

describe("payloadRole / isServiceRolePayload", () => {
  it("reads the role claim as a string or null", () => {
    expect(payloadRole({ role: "anon" })).toBe("anon");
    expect(payloadRole({ role: 5 })).toBeNull();
    expect(payloadRole(null)).toBeNull();
  });
  it("flags only service_role", () => {
    expect(isServiceRolePayload({ role: "service_role" })).toBe(true);
    expect(isServiceRolePayload({ role: "anon" })).toBe(false);
    expect(isServiceRolePayload({ role: "authenticated" })).toBe(false);
    expect(isServiceRolePayload(null)).toBe(false);
  });
});

describe("findServiceRoleJwtLiterals", () => {
  it("finds a service_role JWT embedded in surrounding code", () => {
    const token = serviceRoleJwt();
    const line = `const key = "${token}"; // supabase admin`;
    expect(findServiceRoleJwtLiterals(line)).toEqual([token]);
  });

  it("ignores anon and authenticated JWTs (they are meant to ship)", () => {
    expect(findServiceRoleJwtLiterals(anonJwt())).toEqual([]);
    expect(findServiceRoleJwtLiterals(authenticatedJwt())).toEqual([]);
  });

  it("ignores dotted strings that are not real tokens", () => {
    expect(findServiceRoleJwtLiterals("version 1.2.3")).toEqual([]);
    expect(findServiceRoleJwtLiterals("host www.example.com")).toEqual([]);
  });

  it("matches on the decoded payload role, independent of header and signature", () => {
    const payload = serviceRoleJwtPayload();
    const seg = payloadSegment(payload);
    // A minimal header and a nonsense signature: only the payload decides.
    const token = `eyJhbGciOiJIUzI1NiJ9.${seg}.Zm9v`;
    expect(findServiceRoleJwtLiterals(token)).toEqual([token]);
    const notService = `eyJhbGciOiJIUzI1NiJ9.${payloadSegment({ role: "anon" })}.Zm9v`;
    expect(findServiceRoleJwtLiterals(notService)).toEqual([]);
  });
});
