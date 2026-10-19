import { describe, expect, it } from "vitest";
import {
  computeExitCode,
  countAtOrAbove,
  isSeverity,
  meetsThreshold,
} from "../../src/cli/exit";
import type { Finding, Severity } from "../../src/lib/scanner/types";

function finding(severity: Severity): Finding {
  return {
    ruleId: "RLS_DISABLED",
    severity,
    file: "a.sql",
    line: 1,
    evidence: "e",
    remediation: "r",
  };
}

describe("meetsThreshold", () => {
  it("is inclusive at the gate severity", () => {
    expect(meetsThreshold(finding("medium"), "medium")).toBe(true);
  });
  it("accepts more severe than the gate", () => {
    expect(meetsThreshold(finding("high"), "medium")).toBe(true);
  });
  it("rejects less severe than the gate", () => {
    expect(meetsThreshold(finding("low"), "medium")).toBe(false);
  });
});

describe("isSeverity", () => {
  it("accepts the four severities", () => {
    for (const s of ["high", "medium", "low", "info"]) expect(isSeverity(s)).toBe(true);
  });
  it("rejects anything else", () => {
    expect(isSeverity("critical")).toBe(false);
    expect(isSeverity("HIGH")).toBe(false);
  });
});

describe("countAtOrAbove", () => {
  const findings = [finding("high"), finding("low")];
  it("counts only findings at or above the gate", () => {
    expect(countAtOrAbove(findings, "high")).toBe(1);
    expect(countAtOrAbove(findings, "low")).toBe(2);
  });
});

describe("computeExitCode", () => {
  it("is 0 for a complete scan with no gate hits", () => {
    expect(computeExitCode(true, 0)).toBe(0);
  });
  it("is 1 for a complete scan with gate hits", () => {
    expect(computeExitCode(true, 2)).toBe(1);
  });
  it("is 2 for an incomplete scan regardless of findings", () => {
    expect(computeExitCode(false, 0)).toBe(2);
    expect(computeExitCode(false, 5)).toBe(2); // incomplete outranks findings
  });
});
