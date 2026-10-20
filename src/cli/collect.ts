import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { runScan } from "../lib/scanner";
import type { ScanResult, ScannedFile } from "../lib/scanner/types";
import { isScannable, isVendoredFile } from "../lib/scanner/scope";

export class UsageError extends Error {}

export interface Caps {
  maxFiles: number;
  maxFileSizeBytes: number;
}

// Conservative hostile-input limits. A Supabase project's tracked migrations and
// source are small text files; anything past these bounds is either noise
// (vendored code, blobs) or an attempt to exhaust the scanner's memory / time.
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
  // A bounded sample of skipped files plus running totals. A hostile tree with
  // millions of files must not make us retain millions of skip records — the caps
  // that drop those files would otherwise be defeated by the bookkeeping itself.
  skipped: SkippedFile[];
  skippedTotal: number;
  skipCounts: Record<SkipReason, number>;
  // True if a file the scanner would otherwise analyze was dropped (oversized,
  // symlinked, unreadable, or pushed out by the file cap). Such a gap means a
  // clean result must never be reported as complete. What counts as "would
  // analyze" is `isScannable` below, so the signal grows with the rules that
  // exist. Vendored paths (node_modules) and never-analyzed files (images,
  // lockfiles) are excluded by design and never count as incomplete.
  inputIncomplete: boolean;
}

const EXCLUDED_DIRS = new Set(["node_modules", "vendor", "third_party", ".git", ".next", ".turbo"]);
const MAX_SKIP_SAMPLE = 1000;

// isScannable / isVendoredFile come from the shared scope module, so the collector
// and the source rules can never disagree about which files count. Widening scope to
// source/env files is also what makes a size/count/symlink skip of a SOURCE file mark
// the scan incomplete — the same "skipped means incomplete" rule now covers slice-3
// inputs, not just SQL.

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
  const skipCounts: Record<SkipReason, number> = {
    size: 0,
    count: 0,
    binary: 0,
    symlink: 0,
    unreadable: 0,
  };
  let skippedTotal = 0;
  let inputIncomplete = false;

  const relOf = (full: string): string => {
    const rel = relative(absRoot, full);
    return sep === "/" ? rel : rel.split(sep).join("/");
  };
  const drop = (rel: string, reason: SkipReason): void => {
    if (isScannable(rel)) inputIncomplete = true;
    skipCounts[reason] += 1;
    skippedTotal += 1;
    if (skipped.length < MAX_SKIP_SAMPLE) skipped.push({ path: rel, reason });
  };

  const visit = (dir: string): void => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // an unreadable directory is simply not descended into
    }
    // Sort for deterministic traversal, so collected paths — and thus output
    // order — never depend on the filesystem's directory order.
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (EXCLUDED_DIRS.has(entry.name)) continue; // never a path out of the project
      const rel = relOf(full);
      // An entry is "of interest" only if a rule could actually analyze it: a
      // scannable extension (SQL, source, env) that is not vendored/generated. We
      // read ONLY those, so non-input files (images, docs) are never read into memory
      // and never consume the file cap. A skip is therefore always a scannable file
      // we intended but could not analyze — which is exactly what marks a scan
      // incomplete.
      const interesting = isScannable(rel) && !isVendoredFile(rel);
      if (entry.isSymbolicLink()) {
        // We never follow symlinks out of the root. A symlink standing in for a real
        // input is a gap we cannot read, so it counts (and makes the scan incomplete).
        if (interesting) drop(rel, "symlink");
        continue;
      }
      if (entry.isDirectory()) {
        visit(full);
        continue;
      }
      if (!entry.isFile()) continue; // sockets, fifos, devices
      if (!interesting) continue; // not our input: ignored, never read, never a skip
      if (files.length >= caps.maxFiles) {
        drop(rel, "count");
        continue;
      }
      let buffer: Buffer;
      try {
        buffer = readFileSync(full);
      } catch {
        drop(rel, "unreadable");
        continue;
      }
      if (buffer.length > caps.maxFileSizeBytes) {
        drop(rel, "size");
        continue;
      }
      if (looksBinary(buffer)) {
        drop(rel, "binary");
        continue;
      }
      files.push({ path: rel, content: buffer.toString("utf8") });
    }
  };

  visit(absRoot);
  files.sort((a, b) => a.path.localeCompare(b.path));
  skipped.sort((a, b) => a.path.localeCompare(b.path));
  return { files, skipped, skippedTotal, skipCounts, inputIncomplete };
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
    // A parse failure (result.complete false) or a dropped scannable file both
    // make the scan incomplete: we never certify input we could not read.
    complete: result.complete && !collection.inputIncomplete,
  };
}
