import { describe, expect, it } from "vitest";
import { formatJson, toSarif } from "../../src/cli/output";
import { RULE_IDS, type ScanResult } from "../../src/lib/scanner/types";

const ESC = String.fromCharCode(0x1b);

function sampleResult(): ScanResult {
  return {
    complete: true,
    findings: [
      {
        ruleId: "RLS_DISABLED",
        severity: "high",
        file: "supabase/migrations/0001.sql",
        line: 3,
        object: "public.todos",
        evidence: `Table public.todos${ESC}[31m has no RLS`,
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
        message: "could not parse: syntax error",
      },
    ],
  };
}

describe("formatJson", () => {
  it("emits stable, parseable JSON with counts and relative files", () => {
    const text = formatJson(sampleResult());
    const report = JSON.parse(text);
    expect(report.tool.name).toBe("supa-scan");
    expect(report.complete).toBe(true);
    expect(report.summary.total).toBe(2);
    expect(report.summary.bySeverity.high).toBe(1);
    expect(report.summary.bySeverity.medium).toBe(1);
    expect(report.summary.parseFailures).toBe(1);
    expect(report.findings[0].ruleId).toBe("RLS_DISABLED");
    expect(report.findings[0].file).toBe("supabase/migrations/0001.sql");
    expect(report.parseFailures[0].ruleId).toBe("PARSE_FAILED");
    // byte-stable: same input, identical string
    expect(formatJson(sampleResult())).toBe(text);
  });

  it("never contains an absolute path and strips control chars from evidence", () => {
    const report = JSON.parse(formatJson(sampleResult()));
    expect(report.findings[0].evidence).not.toContain(ESC);
    expect(JSON.stringify(report)).not.toContain("/home/");
  });
});

describe("toSarif", () => {
  it("is a SARIF 2.1.0 log with one run, all rule descriptors, and mapped results", () => {
    const sarif = JSON.parse(toSarif(sampleResult()));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe("supa-scan");
    expect(driver.rules).toHaveLength(RULE_IDS.length);
    expect(driver.rules.map((r: { id: string }) => r.id)).toEqual([...RULE_IDS]);

    const results = sarif.runs[0].results;
    expect(results).toHaveLength(3); // 2 findings + 1 parse failure
    const first = results[0];
    expect(first.ruleId).toBe("RLS_DISABLED");
    expect(first.level).toBe("error"); // high -> error
    expect(first.locations[0].physicalLocation.artifactLocation.uri).toBe(
      "supabase/migrations/0001.sql",
    );
    expect(first.locations[0].physicalLocation.artifactLocation.uriBaseId).toBe("%SRCROOT%");
    expect(first.locations[0].physicalLocation.region.startLine).toBe(3);
    expect(first.properties["security-severity"]).toBe("8.0");

    const view = results[1];
    expect(view.level).toBe("warning"); // medium -> warning
    expect(view.ruleIndex).toBe(RULE_IDS.indexOf("VIEW_NO_SECURITY_INVOKER"));

    const failure = results[2];
    expect(failure.ruleId).toBe("PARSE_FAILED");
  });

  it("strips terminal control characters from SARIF messages too", () => {
    const sarif = JSON.parse(toSarif(sampleResult()));
    const messageText = sarif.runs[0].results[0].message.text as string;
    expect(messageText).not.toContain(ESC);
    expect(messageText).toContain("has no RLS");
  });
});
