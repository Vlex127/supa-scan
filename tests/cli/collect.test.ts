import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { UsageError, collectFiles, type Caps } from "../../src/cli/collect";

let root = "";
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "supa-scan-collect-"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function write(rel: string, content: string | Buffer): void {
  const full = join(root, rel);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

const BIG: Caps = { maxFiles: 5000, maxFileSizeBytes: 1024 * 1024 };

describe("collectFiles", () => {
  it("collects .sql files with paths relative to the root", () => {
    write("supabase/migrations/0001.sql", "create table public.t (id int);");
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toEqual(["supabase/migrations/0001.sql"]);
    expect(result.files[0].content).toContain("create table");
    expect(result.inputIncomplete).toBe(false);
    expect(result.skipped).toHaveLength(0);
  });

  it("never leaks an absolute path into a collected path", () => {
    write("a.sql", "select 1;");
    const [file] = collectFiles(root, BIG).files;
    expect(file.path.startsWith("/")).toBe(false);
    expect(file.path).toBe("a.sql");
  });

  it("excludes node_modules and .git entirely", () => {
    write("keep.sql", "select 1;");
    write("node_modules/pkg/vendored.sql", "select 2;");
    write(".git/hooks/x.sql", "select 3;");
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toEqual(["keep.sql"]);
    // Excluded dirs are not reported as skips and do not make the scan incomplete.
    expect(result.skipped).toHaveLength(0);
    expect(result.inputIncomplete).toBe(false);
  });

  it("does not follow symlinks, and a symlinked .sql marks the scan incomplete", () => {
    write("real.sql", "select 1;");
    symlinkSync(join(root, "real.sql"), join(root, "link.sql"));
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toContain("real.sql");
    expect(result.skipped.some((s) => s.path === "link.sql" && s.reason === "symlink")).toBe(true);
    expect(result.inputIncomplete).toBe(true);
  });

  it("skips an oversized .sql and marks the scan incomplete", () => {
    write("small.sql", "select 1;");
    write("huge.sql", "x".repeat(200));
    const result = collectFiles(root, { maxFiles: 5000, maxFileSizeBytes: 50 });
    expect(result.files.map((f) => f.path)).toContain("small.sql");
    expect(result.skipped.some((s) => s.path === "huge.sql" && s.reason === "size")).toBe(true);
    expect(result.inputIncomplete).toBe(true);
  });

  it("ignores non-scannable files entirely — never read, never a skip, not incomplete", () => {
    write("notes.sql", "select 1;");
    write("README.md", "# docs");
    write("blob.dat", Buffer.from([0x61, 0x00, 0x62]));
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toEqual(["notes.sql"]);
    // .md and .dat are not our input, so they are not even recorded as skips.
    expect(result.skipped).toHaveLength(0);
    expect(result.inputIncomplete).toBe(false);
  });

  it("skips a scannable-extension file whose bytes are binary and marks the scan incomplete", () => {
    write("good.sql", "select 1;");
    write("corrupt.sql", Buffer.from([0x73, 0x00, 0x65])); // NUL in a .sql
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toEqual(["good.sql"]);
    expect(result.skipped.some((s) => s.path === "corrupt.sql" && s.reason === "binary")).toBe(
      true,
    );
    expect(result.inputIncomplete).toBe(true); // we intended to read this SQL but could not
  });

  it("caps the file count and marks the scan incomplete when .sql files are pushed out", () => {
    write("a.sql", "select 1;");
    write("b.sql", "select 2;");
    write("c.sql", "select 3;");
    const result = collectFiles(root, { maxFiles: 2, maxFileSizeBytes: 1024 * 1024 });
    expect(result.files).toHaveLength(2);
    expect(result.skipped.every((s) => s.reason === "count")).toBe(true);
    expect(result.inputIncomplete).toBe(true);
  });

  it("collects source and env files as scannable input, not just SQL", () => {
    write("app/db.ts", "export const x = 1;");
    write("config.json", "{}");
    write(".env", "A=1");
    write("notes.md", "not scanned");
    const paths = collectFiles(root, BIG).files.map((f) => f.path);
    expect(paths).toEqual([".env", "app/db.ts", "config.json"]); // notes.md is not scannable
  });

  it("skips lockfiles and minified bundles without marking the scan incomplete", () => {
    write("keep.sql", "select 1;");
    write("package-lock.json", "x".repeat(10_000));
    write("dist/app.min.js", "y".repeat(10_000));
    write("dist/app.js.map", "{}");
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toEqual(["keep.sql"]);
    // Vendored/generated files are excluded by design, not "skipped input".
    expect(result.skipped).toHaveLength(0);
    expect(result.inputIncomplete).toBe(false);
  });

  it("reads a real .env but never a .env.example template", () => {
    write(".env", "REAL=1");
    write(".env.example", "PLACEHOLDER=changeme");
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toEqual([".env"]);
    expect(result.skipped).toHaveLength(0);
    expect(result.inputIncomplete).toBe(false);
  });

  it("marks the scan incomplete when a SOURCE file is skipped for size", () => {
    write("small.ts", "export const a = 1;");
    write("huge.ts", "x".repeat(200));
    const result = collectFiles(root, { maxFiles: 5000, maxFileSizeBytes: 50 });
    expect(result.files.map((f) => f.path)).toContain("small.ts");
    expect(result.skipped.some((s) => s.path === "huge.ts" && s.reason === "size")).toBe(true);
    expect(result.inputIncomplete).toBe(true); // the "skipped means incomplete" rule now covers source too
  });

  it("throws a UsageError for a missing root or a file root", () => {
    expect(() => collectFiles(join(root, "nope"))).toThrow(UsageError);
    write("file.txt", "x");
    expect(() => collectFiles(join(root, "file.txt"))).toThrow(UsageError);
  });
});
