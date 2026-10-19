import type { Finding, ParseFailure, ScanResult, Severity } from "../lib/scanner/types";
import { RULE_IDS } from "../lib/scanner/types";
import {
  RULE_METADATA,
  SARIF_LEVEL,
  SECURITY_SEVERITY,
  type RuleDescriptor,
} from "../lib/scanner/rule-metadata";
import { stripControl } from "./escape";

export const TOOL_NAME = "supa-scan";
export const TOOL_VERSION = "0.1.0";

interface Summary {
  total: number;
  bySeverity: Record<Severity, number>;
  byRule: Record<string, number>;
  parseFailures: number;
}

function summarize(findings: Finding[], parseFailures: ParseFailure[]): Summary {
  const bySeverity: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  const byRule: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] += 1;
    byRule[f.ruleId] = (byRule[f.ruleId] ?? 0) + 1;
  }
  for (const p of parseFailures) {
    byRule[p.ruleId] = (byRule[p.ruleId] ?? 0) + 1;
  }
  return {
    total: findings.length,
    bySeverity,
    byRule: Object.fromEntries(Object.keys(byRule).sort().map((k) => [k, byRule[k]])),
    parseFailures: parseFailures.length,
  };
}

// Findings/parse failures come pre-sorted by the engine (severity, then file,
// then line). We re-assert that order and emit fixed key order so the JSON is
// byte-stable across runs — CI diffs and SARIF uploads depend on determinism.
function emitFinding(f: Finding): Record<string, unknown> {
  const out: Record<string, unknown> = {
    ruleId: f.ruleId,
    severity: f.severity,
    file: stripControl(f.file),
    line: f.line,
  };
  if (f.object !== undefined) out.object = stripControl(f.object);
  out.evidence = stripControl(f.evidence);
  out.remediation = stripControl(f.remediation);
  return out;
}

function emitParseFailure(p: ParseFailure): Record<string, unknown> {
  return {
    ruleId: p.ruleId,
    severity: p.severity,
    file: stripControl(p.file),
    line: p.line,
    message: stripControl(p.message),
  };
}

// The human/CI JSON report. Paths are always project-relative (the collector
// guarantees it); the scanned root's absolute path never appears anywhere.
export function formatJson(result: ScanResult): string {
  const report = {
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    complete: result.complete,
    summary: summarize(result.findings, result.parseFailures),
    findings: result.findings.map(emitFinding),
    parseFailures: result.parseFailures.map(emitParseFailure),
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}

interface SarifArtifact {
  uri: string;
  uriBaseId: string;
}

function messageText(f: Finding): string {
  return stripControl(`${f.evidence} ${f.remediation}`);
}

function sarifRule(descriptor: RuleDescriptor): Record<string, unknown> {
  return {
    id: descriptor.id,
    name: descriptor.name,
    shortDescription: { text: descriptor.shortDescription },
    fullDescription: { text: descriptor.fullDescription },
    helpUri: "https://supabase.com/docs/guides/database/postgres/row-level-security",
    properties: {
      "security-severity": SECURITY_SEVERITY[descriptor.defaultSeverity],
      tags: ["security", "supabase"],
    },
    defaultConfiguration: { level: SARIF_LEVEL[descriptor.defaultSeverity] },
  };
}

// SARIF 2.1.0. Every result references a rule by id and index, carries a
// relative artifact location and a start line, and maps severity to a SARIF
// level. No secret values are present (the engine masks them before they reach
// a finding), and all scanned-origin strings are control-character stripped.
export function toSarif(result: ScanResult): string {
  const rules = RULE_IDS.map((id) => sarifRule(RULE_METADATA[id]));
  const ruleIndex = new Map(RULE_IDS.map((id, i) => [id, i] as const));

  const results: Record<string, unknown>[] = [];
  for (const f of result.findings) {
    const artifact: SarifArtifact = { uri: stripControl(f.file), uriBaseId: "%SRCROOT%" };
    const properties: Record<string, unknown> = {
      "security-severity": SECURITY_SEVERITY[f.severity],
    };
    if (f.object !== undefined) properties.object = stripControl(f.object);
    results.push({
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId),
      level: SARIF_LEVEL[f.severity],
      locations: [{ physicalLocation: { artifactLocation: artifact, region: { startLine: f.line } } }],
      message: { text: messageText(f) },
      properties,
    });
  }
  for (const p of result.parseFailures) {
    const artifact: SarifArtifact = { uri: stripControl(p.file), uriBaseId: "%SRCROOT%" };
    results.push({
      ruleId: p.ruleId,
      ruleIndex: ruleIndex.get(p.ruleId),
      level: SARIF_LEVEL[p.severity],
      locations: [
        { physicalLocation: { artifactLocation: artifact, region: { startLine: p.line } } },
      ],
      message: { text: stripControl(p.message) },
      properties: { "security-severity": SECURITY_SEVERITY[p.severity] },
    });
  }

  const log = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: "https://github.com/Vlex127/supa-scan",
            rules,
          },
        },
        results,
      },
    ],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}
