import { describe, expect, it } from "vitest";
import { parseArgs, type RunOptions } from "../../src/cli/args";

function runOpts(argv: string[]): RunOptions {
  const parsed = parseArgs(argv);
  if (parsed.kind !== "run") throw new Error(`expected run, got ${parsed.kind}`);
  return parsed.options;
}

describe("parseArgs", () => {
  it("defaults root to '.', format json, fail-on info", () => {
    expect(runOpts([])).toEqual({ root: ".", format: "json", failOn: "info" });
  });

  it("takes a positional root", () => {
    expect(runOpts(["apps/web"]).root).toBe("apps/web");
  });

  it("tolerates the `scan` subcommand", () => {
    expect(runOpts(["scan", "proj"])).toEqual({ root: "proj", format: "json", failOn: "info" });
  });

  it("parses --format both with space and with equals", () => {
    expect(runOpts(["--format", "sarif"]).format).toBe("sarif");
    expect(runOpts(["--format=sarif"]).format).toBe("sarif");
  });

  it("parses --fail-on both with space and with equals", () => {
    expect(runOpts(["--fail-on", "high"]).failOn).toBe("high");
    expect(runOpts(["--fail-on=low"]).failOn).toBe("low");
  });

  it("recognizes help and version", () => {
    expect(parseArgs(["--help"]).kind).toBe("help");
    expect(parseArgs(["-h"]).kind).toBe("help");
    expect(parseArgs(["--version"]).kind).toBe("version");
  });

  it("flags an unknown option", () => {
    const parsed = parseArgs(["--wat"]);
    expect(parsed.kind).toBe("usageError");
  });

  it("flags an invalid --format value", () => {
    expect(parseArgs(["--format", "xml"]).kind).toBe("usageError");
  });

  it("flags an invalid --fail-on value", () => {
    expect(parseArgs(["--fail-on", "critical"]).kind).toBe("usageError");
  });

  it("flags a missing option value", () => {
    expect(parseArgs(["--format"]).kind).toBe("usageError");
    expect(parseArgs(["--format="]).kind).toBe("usageError");
  });

  it("flags a second positional argument", () => {
    expect(parseArgs(["a", "b"]).kind).toBe("usageError");
  });
});
