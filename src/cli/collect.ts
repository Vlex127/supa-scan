import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { runScan } from "../lib/scanner";
import type { ScanResult, ScannedFile } from "../lib/scanner/types";

export class UsageError extends Error {}

export interface Caps {
  maxFiles: number;
  maxFileSizeBytes: number;
}

// Conservative hostile-input limits. A Supabase project's tracked migrations are
// small text files; anything past these bounds is either noise (vendored code,
// blobs) or an attempt to exhaust the scanner's memory / time.
export const DEFAULT_CAPS: Caps = {
  maxFiles: 5000,
  maxFileSizeBytes: 1024 * 1024, // 1 MiB per file
};

export type SkipReason = "size" | "count" | "binary" | "symlink" | "unreadable";

export interface SkippedFile {
  path: string;
  reason: SkipReason;
}

export interface CollectionResult {
  files: ScannedFile[];
  skipped: SkippedFile[];
  // True if a .sql file was dropped (oversized, symlinked, unreadable, or pushed
  // out by the file cap): the schema state would then be missing input, so a
  // clean result must not be reported as complete. Vendored paths like
  // node_modules are excluded by design and never count as incomplete.
  schemaIncomplete: boolean;
}

const EXCLUDED_DIRS = new Set(["node_modules", ".git", ".next", ".turbo"]);

function isSql(path: string): boolean {
  return path.toLowerCase().endsWith(".sql");
}

// A NUL byte in the first 8 KiB marks a binary blob. Real SQL / source text never
// contains one; this avoids reading or emitting megabytes of junk.
function looksBinary(buffer: Buffer): boolean {
  const end = Math.min(buffer.length, 8192);
  for (let i = 0; i < end; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

export function collectFiles(root: string, caps: Caps = DEFAULT_CAPS): CollectionResult {
  const absRoot = resolve(root);
  let rootStat;
  try {
    rootStat = statSync(absRoot);
  } catch {
    throw new UsageError(`root is not a readable directory: ${root}`);
  }
  if (!rootStat.isDirectory()) {
    throw new UsageError(`root is not a directory: ${root}`);
  }

  const files: ScannedFile[] = [];
  const skipped: SkippedFile[] = [];
  let schemaIncomplete = false;

  const relOf = (full: string): string => {
    const rel = relative(absRoot, full);
    return sep === "/" ? rel : rel.split(sep).join("/");
  };
  const drop = (full: string, reason: SkipReason): void => {
    if (isSql(relOf(full))) schemaIncomplete = true;
    skipped.push({ path: relOf(full), reason });
  };

  const visit = (dir: string): void => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // an unreadable directory is simply not descended into
    }
    // Sort for deterministic traversal so collected paths and thus output order
    // do not depend on the filesystem's directory order.
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (EXCLUDED_DIRS.has(entry.name)) continue; // never a path out of the project
      if (entry.isSymbolicLink()) {
        drop(full, "symlink"); // we never follow symlinks out of the root
        continue;
      }
      if (entry.isDirectory()) {
        visit(full);
        continue;
      }
      if (!entry.isFile()) continue; // sockets, fifos, devices
      if (files.length >= caps.maxFiles) {
        drop(full, "count");
        continue;
      }
      let buffer: Buffer;
      try {
        buffer = readFileSync(full);
      } catch {
        drop(full, "unreadable");
        continue;
      }
      if (buffer.length > caps.maxFileSizeBytes) {
        drop(full, "size");
        continue;
      }
      if (looksBinary(buffer)) {
        drop(full, "binary");
        continue;
      }
      files.push({ path: relOf(full), content: buffer.toString("utf8") });
    }
  };

  visit(absRoot);
  files.sort((a, b) => a.path.localeCompare(b.path));
  skipped.sort((a, b) => a.path.localeCompare(b.path));
  return { files, skipped, schemaIncomplete };
}

// Scan a directory on disk into the engine's result, plus the collector's own
// incompleteness signal. Split out from the printer so tests can drive the scan
// without capturing stdout.
export interface ScanOutcome {
  result: ScanResult;
  collection: CollectionResult;
  complete: boolean;
}

export async function scanRoot(root: string, caps: Caps = DEFAULT_CAPS): Promise<ScanOutcome> {
  const collection = collectFiles(root, caps);
  const result = await runScan(collection.files);
  return {
    result,
    collection,
    // A parse failure (result.complete false) or a dropped schema file both make
    // the scan incomplete: we never certify input we could not read.
    complete: result.complete && !collection.schemaIncomplete,
  };
}
