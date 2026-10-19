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
    expect(result.schemaIncomplete).toBe(false);
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
    expect(result.schemaIncomplete).toBe(false);
  });

  it("does not follow symlinks, and a symlinked .sql marks the scan incomplete", () => {
    write("real.sql", "select 1;");
    symlinkSync(join(root, "real.sql"), join(root, "link.sql"));
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toContain("real.sql");
    expect(result.skipped.some((s) => s.path === "link.sql" && s.reason === "symlink")).toBe(true);
    expect(result.schemaIncomplete).toBe(true);
  });

  it("skips an oversized .sql and marks the scan incomplete", () => {
    write("small.sql", "select 1;");
    write("huge.sql", "x".repeat(200));
    const result = collectFiles(root, { maxFiles: 5000, maxFileSizeBytes: 50 });
    expect(result.files.map((f) => f.path)).toContain("small.sql");
    expect(result.skipped.some((s) => s.path === "huge.sql" && s.reason === "size")).toBe(true);
    expect(result.schemaIncomplete).toBe(true);
  });

  it("skips binary files (a NUL byte) without marking schema incomplete", () => {
    write("notes.sql", "select 1;");
    write("blob.dat", Buffer.from([0x61, 0x00, 0x62]));
    const result = collectFiles(root, BIG);
    expect(result.files.map((f) => f.path)).toEqual(["notes.sql"]);
    expect(result.skipped.some((s) => s.path === "blob.dat" && s.reason === "binary")).toBe(true);
    expect(result.schemaIncomplete).toBe(false);
  });

  it("caps the file count and marks the scan incomplete when .sql files are pushed out", () => {
    write("a.sql", "select 1;");
    write("b.sql", "select 2;");
    write("c.sql", "select 3;");
    const result = collectFiles(root, { maxFiles: 2, maxFileSizeBytes: 1024 * 1024 });
    expect(result.files).toHaveLength(2);
    expect(result.skipped.every((s) => s.reason === "count")).toBe(true);
    expect(result.schemaIncomplete).toBe(true);
  });

  it("throws a UsageError for a missing root or a file root", () => {
    expect(() => collectFiles(join(root, "nope"))).toThrow(UsageError);
    write("file.txt", "x");
    expect(() => collectFiles(join(root, "file.txt"))).toThrow(UsageError);
  });
});
