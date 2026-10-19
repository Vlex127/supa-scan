import { USAGE, parseArgs } from "./args";
import { UsageError, DEFAULT_CAPS, scanRoot, type Caps } from "./collect";
import { TOOL_NAME, TOOL_VERSION, formatJson, toSarif } from "./output";
import { computeExitCode, countAtOrAbove } from "./exit";
import { stripControl } from "./escape";

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
export async function run(argv: readonly string[], io: Io = DEFAULT_IO, caps: Caps = DEFAULT_CAPS): Promise<0 | 1 | 2> {
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
    const gateHits = countAtOrAbove(outcome.result.findings, failOn);
    const exit = computeExitCode(outcome.complete, gateHits);

    const body = format === "sarif" ? toSarif(outcome.result) : formatJson(outcome.result);
    io.stdout(body);

    if (!outcome.complete) {
      const notes: string[] = [];
      if (outcome.result.parseFailures.length > 0) {
        notes.push(
          `${outcome.result.parseFailures.length} file(s) could not be parsed`,
        );
      }
      if (outcome.collection.schemaIncomplete) {
        notes.push("a SQL file was skipped (size, count, symlink, or unreadable)");
      }
      io.stderr(`supa-scan: scan is incomplete — ${notes.join("; ")} (exit 2)\n`);
    }
    return exit;
  } catch (error) {
    if (error instanceof UsageError) {
      io.stderr(`${stripControl(error.message)}\n`);
      return 2;
    }
    io.stderr(`supa-scan: ${stripControl(String(error))}\n`);
    return 2;
  }
}

// Referenced to keep the collector's default caps exported through this module's
// surface without callers importing collect directly.
export { DEFAULT_CAPS };
