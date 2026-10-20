import { describe, expect, it } from "vitest";
import { runScan } from "../index";
import type { Finding, ScannedFile } from "../types";
import { keyServiceRoleClient } from "../rules/key-service-role-client";
import { secretCommitted } from "../rules/secret-committed";
import { CHUNK_WINDOW } from "../masking";
import {
  anonJwt,
  authenticatedJwt,
  personalAccessToken,
  payloadSegment,
  serviceRoleJwt,
  supabasePublishableKey,
  supabaseSecretKey,
} from "../../../../tests/helpers/build-token";

function src(path: string, content: string): ScannedFile {
  return { path, content };
}

// Concatenate every field a finding could surface, so a masking assertion checks
// the whole record, not just `evidence`.
function haystack(finding: Finding): string {
  return `${finding.evidence}\n${finding.object ?? ""}\n${JSON.stringify(finding)}`;
}

function ruleIds(findings: Finding[]): string[] {
  return findings.map((f) => f.ruleId);
}

describe("KEY_SERVICE_ROLE_CLIENT", () => {
  it("(a) flags a NEXT_PUBLIC_* name mentioning SERVICE_ROLE or SECRET, value-independent", () => {
    const out = keyServiceRoleClient([
      src(
        "app/lib/supabase.ts",
        "const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n" +
          "const u = process.env.NEXT_PUBLIC_SUPABASE_URL;\n" +
          "const s = process.env.NEXT_PUBLIC_APP_SECRET;\n",
      ),
    ]);
    // Two leaks (the SERVICE_ROLE name and the SECRET name); the URL name is clean.
    expect(out).toHaveLength(2);
    expect(out.every((f) => f.severity === "high")).toBe(true);
    expect(out.map((f) => f.object)).toEqual([
      "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
      "NEXT_PUBLIC_APP_SECRET",
    ]);
    expect(out.map((f) => f.line)).toEqual([1, 3]);
  });

  it("(a) does not fire on a NEXT_PUBLIC_ run inside a longer identifier", () => {
    const out = keyServiceRoleClient([src("a.ts", 'const v = "ENV_NEXT_PUBLIC_SERVICE_ROLE";')]);
    expect(out).toHaveLength(0);
  });

  it("(b) flags a service-role reference only in a 'use client' module", () => {
    const client = keyServiceRoleClient([
      src("client.ts", "'use client';\nconst token = SUPABASE_SERVICE_ROLE_TOKEN;\n"),
    ]);
    expect(client).toHaveLength(1);
    expect(client[0].severity).toBe("high");
    expect(client[0].line).toBe(2);

    const server = keyServiceRoleClient([src("server.ts", "const token = SERVICE_ROLE_TOKEN;\n")]);
    expect(server).toHaveLength(0); // same reference, not client code, no JWT/name
  });

  it("(c) flags a service_role JWT in source as critical; never anon or authenticated", () => {
    const token = serviceRoleJwt();
    const crit = keyServiceRoleClient([src("leak.ts", `const key = "${token}";`)]);
    expect(crit).toHaveLength(1);
    expect(crit[0].severity).toBe("critical");
    // masking: the token appears nowhere in the finding.
    expect(haystack(crit[0])).not.toContain(token);
    expect(haystack(crit[0])).not.toContain(payloadSegment({ role: "service_role" }));

    expect(keyServiceRoleClient([src("a.ts", anonJwt())])).toHaveLength(0);
    expect(keyServiceRoleClient([src("a.ts", authenticatedJwt())])).toHaveLength(0);
  });

  it("(c) detects a service_role JWT parked past 3000 characters on one long line", () => {
    // The old scanner skipped lines over 2000 chars — a silent blindable evasion. A
    // credential buried in a long (generated-looking) line must still be found.
    const token = serviceRoleJwt();
    const prefix = "/* " + "A".repeat(3000) + " */ const key = ";
    const out = keyServiceRoleClient([src("bundle.ts", prefix + `"${token}";`)]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("critical");
    expect(out[0].line).toBe(1);
    expect(haystack(out[0])).not.toContain(token);
  });

  it("(c) detects a JWT that straddles a chunk boundary (overlap covers it once)", () => {
    // Place the token so its start sits just before a window cut. The preceding
    // window sees only a truncated fragment (which must not false-positive); the
    // overlapping window contains the whole token, so exactly one finding results.
    const token = serviceRoleJwt();
    const prefix = "x".repeat(CHUNK_WINDOW - 40) + 'const key = "';
    const out = keyServiceRoleClient([src("big.ts", prefix + token + '";')]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("critical");
    expect(haystack(out[0])).not.toContain(token);
  });
});

describe("SECRET_COMMITTED", () => {
  it("flags sb_secret_ and sbp_ keys in any source, but never a publishable key", () => {
    const secret = supabaseSecretKey();
    const pat = personalAccessToken();
    const pub = supabasePublishableKey();

    const secretFindings = secretCommitted([src("a.ts", `const k = "${secret}";`)]);
    expect(secretFindings).toHaveLength(1);
    expect(ruleIds(secretFindings)).toEqual(["SECRET_COMMITTED"]);
    expect(haystack(secretFindings[0])).not.toContain(secret);

    expect(secretCommitted([src("b.ts", pat)])).toHaveLength(1);
    // publishable is the public anon replacement — never a secret.
    expect(secretCommitted([src("c.ts", pub)])).toHaveLength(0);
  });

  it("flags an sb_secret_ key buried past the 2000-char line the old scanner skipped", () => {
    const secret = supabaseSecretKey();
    const prefix = "/*" + "z".repeat(2500) + "*/ const k = ";
    const out = secretCommitted([src("bundle.ts", prefix + `"${secret}";`)]);
    expect(out).toHaveLength(1);
    expect(out[0].line).toBe(1);
    expect(haystack(out[0])).not.toContain(secret);
  });

  it("flags a PEM private-key block (the header line, which is not itself secret)", () => {    const pem = secretCommitted([
      src("key.ts", 'const p = "-----BEGIN RSA PRIVATE KEY-----";'),
    ]);
    expect(pem).toHaveLength(1);
    expect(pem[0].evidence).toContain("PRIVATE KEY");
  });

  it("flags a service_role JWT committed in a .env file", () => {
    const token = serviceRoleJwt();
    const out = secretCommitted([src(".env", `SUPABASE_KEY=${token}\n`)]);
    expect(out).toHaveLength(1);
    expect(ruleIds(out)).toEqual(["SECRET_COMMITTED"]);
    expect(haystack(out[0])).not.toContain(token);
  });

  it("flags a key-like name with a real value in .env, not a placeholder or a benign name", () => {
    const env = (text: string) => secretCommitted([src(".env", text)]);
    expect(env("ADMIN_PASSWORD=hunter2something\n")).toHaveLength(1);
    expect(env('API_KEY=""\n')).toHaveLength(0); // empty
    expect(env("API_KEY=\n")).toHaveLength(0); // empty
    expect(env("DATABASE_URL=postgres://localhost/db\n")).toHaveLength(0); // not a secret name
    expect(env("FOO=barbazqux\n")).toHaveLength(0); // benign name
    // The secret value itself is never echoed.
    const one = env("CLIENT_SECRET=abcdef123456\n");
    expect(one).toHaveLength(1);
    expect(haystack(one[0])).not.toContain("abcdef123456");
  });

  it("reports one finding per line when a format match already covered a secret name", () => {
    // SUPABASE_SECRET_KEY is a secret name AND holds an sb_secret_ value; the value
    // match owns the line so the generic name rule does not double-report it.
    const out = secretCommitted([src(".env", `SUPABASE_SECRET_KEY=${supabaseSecretKey()}\n`)]);
    expect(out).toHaveLength(1);
  });

  it("runs high-confidence detectors on a .env TEMPLATE but skips the generic name check", () => {
    const secret = supabaseSecretKey();
    const token = serviceRoleJwt();
    // Real credentials pasted into a template are still caught...
    expect(secretCommitted([src(".env.example", `KEY=${secret}\n`)]).map((f) => f.ruleId)).toEqual(
      ["SECRET_COMMITTED"],
    );
    expect(secretCommitted([src(".env.example", `SUPABASE_KEY=${token}\n`)]).length).toBe(1);
    expect(secretCommitted([src(".env.example", "P=-----BEGIN PRIVATE KEY-----\n")]).length).toBe(
      1,
    );
    // ...but a placeholder on a secret-shaped name is NOT flagged (templates are
    // meant to hold them; only the generic check is suppressed, not the formats).
    expect(secretCommitted([src(".env.example", "API_KEY=your-key-here\n")])).toHaveLength(0);
    expect(secretCommitted([src(".env.example", "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n")])).toHaveLength(
      0,
    );
  });

  it("still runs the generic secret-name check on a REAL env file", () => {
    // Same placeholder-shaped line, but in a real .env it is treated as a leak.
    const out = secretCommitted([src(".env", "API_KEY=abcdef123456\n")]);
    expect(out).toHaveLength(1);
    expect(haystack(out[0])).not.toContain("abcdef123456");
  });
});

describe("runScan integration (schema + text rules, ordering)", () => {
  it("sorts a critical source finding ahead of an SQL high finding", async () => {
    const token = serviceRoleJwt();
    const files = [
      src("supabase/migrations/0001.sql", "create table public.todos (id int);\n"),
      src("app/leak.ts", `const key = "${token}";`),
    ];
    const result = await runScan(files);
    expect(result.complete).toBe(true);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.findings[0].ruleId).toBe("KEY_SERVICE_ROLE_CLIENT");
    expect(result.findings.some((f) => f.ruleId === "RLS_DISABLED")).toBe(true);
  });

  it("yields zero findings for a secure project using only public credentials", async () => {
    const files = [
      src(
        "supabase/migrations/0001.sql",
        "create table public.todos (id int, user_id uuid);\n" +
          "alter table public.todos enable row level security;\n" +
          'create policy "own rows" on public.todos for select using ((select auth.uid()) = user_id);\n',
      ),
      src(
        "app/lib/supabase.ts",
        "const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\n" +
          `const pubKey = "${supabasePublishableKey()}";\n` +
          `const session = "${anonJwt()}";\n`,
      ),
    ];
    const result = await runScan(files);
    expect(result.complete).toBe(true);
    expect(result.findings).toHaveLength(0);
  });
});
