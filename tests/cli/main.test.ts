import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../../src/cli/main";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));

interface Captured {
  code: number;
  out: string;
  err: string;
}

async function capture(argv: string[]): Promise<Captured> {
  let out = "";
  let err = "";
  const code = await run(argv, {
    stdout: (chunk) => {
      out += chunk;
    },
    stderr: (chunk) => {
      err += chunk;
    },
  });
  return { code, out, err };
}

const tmpDirs: string[] = [];
function freshTmp(): string {
  const dir = mkdtempSync(join(tmpdir(), "supa-scan-main-"));
  tmpDirs.push(dir);
  return dir;
}
afterEach(() => {
  while (tmpDirs.length) rmSync(tmpDirs.pop() ?? "", { recursive: true, force: true });
});

describe("run (CLI end-to-end)", () => {
  it("exits 0 on the secure fixture with a complete, empty report", async () => {
    const { code, out } = await capture([join(REPO_ROOT, "fixtures", "secure")]);
    expect(code).toBe(0);
    const report = JSON.parse(out);
    expect(report.complete).toBe(true);
    expect(report.findings).toHaveLength(0);
  });

  it("exits 1 on the insecure fixture and reports the findings", async () => {
    const { code, out } = await capture([join(REPO_ROOT, "fixtures", "insecure")]);
    expect(code).toBe(1);
    const report = JSON.parse(out);
    expect(report.complete).toBe(true);
    const ruleIds = new Set(report.findings.map((f: { ruleId: string }) => f.ruleId));
    expect(ruleIds.has("RLS_DISABLED")).toBe(true);
    expect(report.summary.total).toBe(report.findings.length);
  });

  it("emits SARIF when asked, with exit 1 for findings", async () => {
    const { code, out } = await capture([
      "--format",
      "sarif",
      join(REPO_ROOT, "fixtures", "insecure"),
    ]);
    expect(code).toBe(1);
    const sarif = JSON.parse(out);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  it("exits 2 on a usage error without printing a report", async () => {
    const { code, out, err } = await capture(["--format", "xml"]);
    expect(code).toBe(2);
    expect(out).toBe("");
    expect(err).toContain("invalid --format");
  });

  it("exits 2 when the root is not a directory", async () => {
    const { code, out } = await capture([join(tmpdir(), "definitely-not-here-xyz")]);
    expect(code).toBe(2);
    expect(out).toBe("");
  });

  it("exits 2 and flags incompleteness when a SQL file cannot be parsed", async () => {
    const dir = freshTmp();
    writeFileSync(join(dir, "0001_ok.sql"), "create table public.t (id int);");
    writeFileSync(join(dir, "0002_bad.sql"), "this is not valid sql ;");
    const { code, out, err } = await capture([dir]);
    expect(code).toBe(2);
    const report = JSON.parse(out);
    expect(report.complete).toBe(false);
    expect(report.parseFailures.length).toBeGreaterThan(0);
    expect(err).toContain("incomplete");
  });

  it("handles --version and --help", async () => {
    expect((await capture(["--version"])).code).toBe(0);
    const help = await capture(["--help"]);
    expect(help.code).toBe(0);
    expect(help.out).toContain("supa-scan");
  });
});
