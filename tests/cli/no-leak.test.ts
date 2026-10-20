import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../../src/cli/main";
import { scanRoot } from "../../src/cli/collect";
import { formatJson, toSarif } from "../../src/cli/output";
import { payloadSegment, serviceRoleJwt, supabaseSecretKey } from "../helpers/build-token";

async function capture(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  let out = "";
  let err = "";
  const code = await run(argv, {
    stdout: (c) => {
      out += c;
    },
    stderr: (c) => {
      err += c;
    },
  });
  return { code, out, err };
}

const dirs: string[] = [];
function freshTmp(): string {
  const dir = mkdtempSync(join(tmpdir(), "supa-scan-leak-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() ?? "", { recursive: true, force: true });
});

describe("secret masking across every output path", () => {
  it("never prints a credential to stdout-JSON, stdout-SARIF, or the report serializers", async () => {
    const dir = freshTmp();
    const token = serviceRoleJwt();
    const secretKey = supabaseSecretKey();
    const payloadSeg = payloadSegment({ role: "service_role" });
    writeFileSync(join(dir, "leak.ts"), `const key = "${token}";\n`);
    writeFileSync(join(dir, ".env"), `SUPABASE_SECRET_KEY=${secretKey}\n`);

    // (1) stdout, JSON format.
    const json = await capture([dir]);
    expect(json.code).toBe(1);
    // (2) stdout, SARIF format.
    const sarif = await capture(["--format", "sarif", dir]);
    expect(sarif.code).toBe(1);

    // (3) + (4) the report serializers called directly.
    const outcome = await scanRoot(dir);
    const report = {
      complete: outcome.complete,
      result: outcome.result,
      skipped: outcome.collection.skipped,
      skippedTotal: outcome.collection.skippedTotal,
      skipCounts: outcome.collection.skipCounts,
    };
    const directJson = formatJson(report);
    const directSarif = toSarif(report);

    // The scan should be complete and should have flagged exactly the leaks.
    expect(outcome.complete).toBe(true);
    const ids = new Set(outcome.result.findings.map((f) => f.ruleId));
    expect(ids.has("KEY_SERVICE_ROLE_CLIENT")).toBe(true);
    expect(ids.has("SECRET_COMMITTED")).toBe(true);
    const critical = outcome.result.findings.find((f) => f.severity === "critical");
    expect(critical?.ruleId).toBe("KEY_SERVICE_ROLE_CLIENT");

    for (const [name, text] of [
      ["stdout json", json.out],
      ["stdout sarif", sarif.out],
      ["direct json", directJson],
      ["direct sarif", directSarif],
    ] as const) {
      expect(text, name).not.toContain(token);
      expect(text, name).not.toContain(payloadSeg);
      expect(text, name).not.toContain(secretKey);
      // The secret body, not merely the exact prefix, must be gone.
      expect(text, name).not.toContain(secretKey.slice("sb_secret_".length));
    }

    // Masking still communicates the finding: a length claim survives.
    expect(directJson).toMatch(/-character value/);
  });

  it("never echoes a credential sitting inside a broken SQL statement", async () => {
    // A credential in unparseable SQL is the PARSE_FAILED leak path: the raw
    // Postgres message interpolates the offending token. The engine reports only a
    // fixed category, so the secret must appear in none of stdout-JSON, stdout-SARIF,
    // or the direct serializers — while the failure is still surfaced.
    const dir = freshTmp();
    const body = randomBytes(16).toString("base64url");
    const leak = `sb_secret_${body}`;
    mkdirSync(join(dir, "supabase", "migrations"), { recursive: true });
    writeFileSync(join(dir, "supabase", "migrations", "0001.sql"), `select '${leak}`);

    const json = await capture([dir]);
    expect(json.code).toBe(2); // incomplete scan
    const sarif = await capture(["--format", "sarif", dir]);
    expect(sarif.code).toBe(2);

    const outcome = await scanRoot(dir);
    const report = {
      complete: outcome.complete,
      result: outcome.result,
      skipped: outcome.collection.skipped,
      skippedTotal: outcome.collection.skippedTotal,
      skipCounts: outcome.collection.skipCounts,
    };
    const directJson = formatJson(report);
    const directSarif = toSarif(report);

    // The failure is still reported (file + position + category), just not its text.
    expect(outcome.complete).toBe(false);
    expect(outcome.result.parseFailures).toHaveLength(1);
    expect(outcome.result.parseFailures[0].category).toBe("unterminated_string");

    for (const [name, text] of [
      ["stdout json", json.out],
      ["stdout sarif", sarif.out],
      ["direct json", directJson],
      ["direct sarif", directSarif],
    ] as const) {
      expect(text, name).not.toContain(leak);
      expect(text, name).not.toContain(body);
    }
  });
});
