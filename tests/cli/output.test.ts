import { describe, expect, it } from "vitest";
import { formatJson, toSarif, type ScanReport } from "../../src/cli/output";
import type { ScanResult } from "../../src/lib/scanner/types";
import { implementedRuleIds } from "../../src/lib/scanner/rule-metadata";

const ESC = String.fromCharCode(0x1b);
const RLO = String.fromCharCode(0x202e);

function sampleScanResult(): ScanResult {
  return {
    complete: true,
    findings: [
      {
        ruleId: "RLS_DISABLED",
        severity: "high",
        file: "supabase/migrations/0001.sql",
        line: 3,
        object: "public.todos",
        evidence: `Table public.todos${ESC}[31m${RLO} has no RLS`,
        remediation: "Enable RLS.",
      },
      {
        ruleId: "VIEW_NO_SECURITY_INVOKER",
        severity: "medium",
        file: "supabase/migrations/0002.sql",
        line: 7,
        object: "public.v",
        evidence: "View public.v lacks security_invoker",
        remediation: "Recreate WITH security_invoker.",
      },
    ],
    parseFailures: [
      {
        ruleId: "PARSE_FAILED",
        severity: "high",
        file: "supabase/migrations/0003.sql",
        line: 1,
        category: "syntax_error",
      },
    ],
  };
}

function report(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    complete: true,
    result: sampleScanResult(),
    skipped: [{ path: "big.sql", reason: "size" }],
    skippedTotal: 1,
    skipCounts: { size: 1, count: 0, binary: 0, symlink: 0, unreadable: 0 },
    ...overrides,
  };
}

describe("formatJson", () => {
  it("emits stable JSON with findings, parse failures, and skip tallies", () => {
    const text = formatJson(report());
    const parsed = JSON.parse(text);
    expect(parsed.tool.name).toBe("supa-scan");
    expect(parsed.complete).toBe(true);
    expect(parsed.summary.total).toBe(2);
    expect(parsed.summary.parseFailures).toBe(1);
    expect(parsed.summary.skipped).toBe(1);
    expect(parsed.findings[0].ruleId).toBe("RLS_DISABLED");
    expect(parsed.parseFailures[0].ruleId).toBe("PARSE_FAILED");
    expect(parsed.parseFailures[0].category).toBe("syntax_error");
    expect(parsed.parseFailures[0].message).toBeUndefined();
    expect(parsed.skipped[0].path).toBe("big.sql");
    expect(formatJson(report())).toBe(text); // byte-stable
  });

  it("strips ESC and visibly escapes the RLO in evidence; never leaks an absolute path", () => {
    const parsed = JSON.parse(formatJson(report()));
    const evidence = parsed.findings[0].evidence as string;
    expect(evidence).not.toContain(ESC);
    expect(evidence).not.toContain(RLO);
    expect(evidence).toContain("202e"); // the visible escape marker
    expect(JSON.stringify(parsed)).not.toContain("/home/");
  });
});

describe("toSarif", () => {
  it("lists only implemented rules and only findings as results", () => {
    const sarif = JSON.parse(toSarif(report()));
    expect(sarif.version).toBe("2.1.0");
    const driver = sarif.runs[0].tool.driver;
    const ids = driver.rules.map((r: { id: string }) => r.id);
    expect(ids).toEqual(implementedRuleIds());
    expect(ids).not.toContain("PARSE_FAILED");
    // Slice 3 shipped the source rules, so they are now advertised (and PARSE_FAILED
    // still is not). implementedRuleIds() is the single source of truth for this.
    expect(ids).toContain("KEY_SERVICE_ROLE_CLIENT");
    expect(ids).toContain("SECRET_COMMITTED");
    expect(driver.rules).toHaveLength(7);
    // results = the two findings only; the parse failure is NOT a result.
    const results = sarif.runs[0].results;
    expect(results).toHaveLength(2);
    expect(results.map((r: { ruleId: string }) => r.ruleId)).not.toContain("PARSE_FAILED");
  });

  it("maps severity to level, keeps relative %SRCROOT% URIs and startLine", () => {
    const results = JSON.parse(toSarif(report())).runs[0].results;
    expect(results[0].level).toBe("error");
    expect(results[1].level).toBe("warning");
    expect(results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(
      "supabase/migrations/0001.sql",
    );
    expect(results[0].locations[0].physicalLocation.artifactLocation.uriBaseId).toBe("%SRCROOT%");
    expect(results[0].locations[0].physicalLocation.region.startLine).toBe(3);
    expect(results[0].properties["security-severity"]).toBe("8.0");
    expect(JSON.stringify(results[0].message.text)).not.toContain(ESC);
  });

  it("reports an incomplete scan via invocations, not as a finding", () => {
    const sarif = JSON.parse(toSarif(report({ complete: false })));
    const inv = sarif.runs[0].invocations[0];
    expect(inv.executionSuccessful).toBe(false);
    const notifIds = inv.toolExecutionNotifications.map(
      (n: { descriptor: { id: string } }) => n.descriptor.id,
    );
    expect(notifIds).toContain("supa-scan/parse-failure");
    expect(notifIds).toContain("supa-scan/file-skipped");
    expect(sarif.runs[0].results).toHaveLength(2); // unchanged: not results
  });

  it("sets executionSuccessful true on a complete scan and includes a skip notification", () => {
    const inv = JSON.parse(toSarif(report({ complete: true }))).runs[0].invocations[0];
    expect(inv.executionSuccessful).toBe(true);
    const ids = inv.toolExecutionNotifications.map((n: { descriptor: { id: string } }) =>
      String(n.descriptor.id)
    );
    expect(ids).toContain("supa-scan/parse-failure");
  });
});
