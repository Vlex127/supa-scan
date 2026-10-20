import { USAGE, parseArgs } from "./args";
import { UsageError, DEFAULT_CAPS, scanRoot, type Caps } from "./collect";
import { TOOL_NAME, TOOL_VERSION, formatJson, toSarif, type ScanReport } from "./output";
import { computeExitCode, countAtOrAbove } from "./exit";
import { sanitizeText } from "./escape";

export interface Io {
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
}

const DEFAULT_IO: Io = {
  stdout: (chunk) => process.stdout.write(chunk),
  stderr: (chunk) => process.stderr.write(chunk),
};

// Drive one CLI invocation and return the process exit code. All filesystem and
// process interaction is isolated here; output building and exit logic are pure.
export async function run(
  argv: readonly string[],
  io: Io = DEFAULT_IO,
  caps: Caps = DEFAULT_CAPS,
): Promise<0 | 1 | 2> {
  const parsed = parseArgs(argv);

  if (parsed.kind === "help") {
    io.stdout(USAGE);
    return 0;
  }
  if (parsed.kind === "version") {
    io.stdout(`${TOOL_NAME} ${TOOL_VERSION}\n`);
    return 0;
  }
  if (parsed.kind === "usageError") {
    io.stderr(`${parsed.message}\n\n${USAGE}`);
    return 2;
  }

  const { root, format, failOn } = parsed.options;

  try {
    const outcome = await scanRoot(root, caps);
    const collection = outcome.collection;
    const report: ScanReport = {
      complete: outcome.complete,
      result: outcome.result,
      skipped: collection.skipped,
      skippedTotal: collection.skippedTotal,
      skipCounts: collection.skipCounts,
    };
    const gateHits = countAtOrAbove(outcome.result.findings, failOn);
    const exit = computeExitCode(outcome.complete, gateHits);

    io.stdout(format === "sarif" ? toSarif(report) : formatJson(report));

    if (!outcome.complete) {
      const notes: string[] = [];
      if (outcome.result.parseFailures.length > 0) {
        notes.push(`${outcome.result.parseFailures.length} file(s) could not be parsed`);
      }
      if (collection.inputIncomplete) {
        notes.push("a scannable file was skipped (size, count, symlink, or unreadable)");
      }
      io.stderr(`supa-scan: scan is incomplete — ${notes.join("; ")} (exit 2)\n`);
    }
    return exit;
  } catch (error) {
    if (error instanceof UsageError) {
      io.stderr(`${sanitizeText(error.message)}\n`);
      return 2;
    }
    io.stderr(`supa-scan: ${sanitizeText(String(error))}\n`);
    return 2;
  }
}

// Re-exported so callers can reuse the default caps without importing collect.
export { DEFAULT_CAPS };
