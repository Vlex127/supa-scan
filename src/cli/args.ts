import type { Severity } from "../lib/scanner/types";
import { isSeverity } from "./exit";

export interface RunOptions {
  root: string;
  format: "json" | "sarif";
  failOn: Severity;
}

export type ParsedArgs =
  | { kind: "run"; options: RunOptions }
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "usageError"; message: string };

export const USAGE = `supa-scan [scan] [options] [root]

A pre-deploy, CI-friendly static security scanner for Supabase projects.

Options:
  --format json|sarif   Output format (default: json).
  --fail-on <severity>  Minimum severity that triggers exit 1: high|medium|low|info
                        (default: info — any finding fails the gate).
  -h, --help            Show this help and exit 0.
  --version             Print the version and exit 0.

Arguments:
  root                  Directory to scan (default: the current directory).

Exit codes:
  0  clean (no finding at or above --fail-on)
  1  one or more findings at or above --fail-on
  2  usage error, tool error, or an incomplete scan
`;

function usageError(message: string): ParsedArgs {
  return { kind: "usageError", message };
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  let root: string | undefined;
  let format: "json" | "sarif" = "json";
  let failOn: Severity = "info";

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];

    if (token === "scan") continue; // tolerate the `supa-scan scan` form
    if (token === "-h" || token === "--help") return { kind: "help" };
    if (token === "--version") return { kind: "version" };

    if (token.startsWith("-")) {
      const eq = token.indexOf("=");
      const name = eq >= 0 ? token.slice(0, eq) : token;

      if (name !== "--format" && name !== "--fail-on") {
        return usageError(`unknown option: ${name}`);
      }

      let value: string | undefined;
      if (eq >= 0) {
        value = token.slice(eq + 1);
        if (value === "") return usageError(`${name} requires a value`);
      } else {
        const next = argv[i + 1];
        if (next === undefined) return usageError(`${name} requires a value`);
        value = next;
        i++;
      }

      if (name === "--format") {
        if (value !== "json" && value !== "sarif") {
          return usageError(`invalid --format: ${value} (expected json or sarif)`);
        }
        format = value;
      } else {
        if (!isSeverity(value)) {
          return usageError(`invalid --fail-on: ${value} (expected high, medium, low or info)`);
        }
        failOn = value;
      }
      continue;
    }

    if (root !== undefined) return usageError(`unexpected argument: ${token}`);
    root = token;
  }

  return { kind: "run", options: { root: root ?? ".", format, failOn } };
}
