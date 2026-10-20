import type {
  Finding,
  ParseErrorCategory,
  ParseFailure,
  ScanResult,
  Severity,
} from "../lib/scanner/types";
import type { SkippedFile, SkipReason } from "./collect";
import {
  RULE_METADATA,
  SARIF_LEVEL,
  SECURITY_SEVERITY,
  implementedRuleIds,
  type RuleDescriptor,
} from "../lib/scanner/rule-metadata";
import { sanitizeText } from "./escape";

export const TOOL_NAME = "supa-scan";
export const TOOL_VERSION = "0.1.0";

// The single input both serializers render. `complete` is the CLI's EFFECTIVE
// completeness (no parse failures AND no dropped scannable file); a scan that
// could not finish is never reported as clean. `skipped` is a bounded sample;
// `skippedTotal` / `skipCounts` carry the full tally.
export interface ScanReport {
  complete: boolean;
  result: ScanResult;
  skipped: SkippedFile[];
  skippedTotal: number;
  skipCounts: Record<SkipReason, number>;
}

const SKIP_REASONS: readonly SkipReason[] = ["size", "count", "binary", "symlink", "unreadable"];
const NOTIFY_CAP = 50; // enumerated parse-failure notifications before a rollup

// Fixed, human-readable phrasing for each parse-failure category. The map's keys are
// the closed ParseErrorCategory set, so a notification never interpolates parser-
// supplied text (which can echo a quoted credential sitting in broken SQL).
const PARSE_CATEGORY_PHRASE: Record<ParseErrorCategory, string> = {
  syntax_error: "syntax error",
  unterminated_string: "unterminated quoted string",
  unterminated_comment: "unterminated block comment",
  unterminated_dollar_quote: "unterminated dollar-quoted string",
  invalid_input: "invalid input syntax",
  parse_error: "could not be parsed",
};

interface Summary {
  total: number;
  bySeverity: Record<Severity, number>;
  byRule: Record<string, number>;
  parseFailures: number;
  skipped: number;
  skipCounts: Record<string, number>;
}

function summarize(report: ScanReport): Summary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byRule: Record<string, number> = {};
  for (const f of report.result.findings) {
    bySeverity[f.severity] += 1;
    byRule[f.ruleId] = (byRule[f.ruleId] ?? 0) + 1;
  }
  const skipCounts: Record<string, number> = {};
  for (const reason of SKIP_REASONS) skipCounts[reason] = report.skipCounts[reason] ?? 0;
  return {
    total: report.result.findings.length,
    bySeverity,
    byRule: Object.fromEntries(Object.keys(byRule).sort().map((k) => [k, byRule[k]])),
    parseFailures: report.result.parseFailures.length,
    skipped: report.skippedTotal,
    skipCounts,
  };
}

function emitFinding(f: Finding): Record<string, unknown> {
  const out: Record<string, unknown> = {
    ruleId: f.ruleId,
    severity: f.severity,
    file: sanitizeText(f.file),
    line: f.line,
  };
  if (f.object !== undefined) out.object = sanitizeText(f.object);
  out.evidence = sanitizeText(f.evidence);
  out.remediation = sanitizeText(f.remediation);
  return out;
}

function emitParseFailure(p: ParseFailure): Record<string, unknown> {
  return {
    ruleId: p.ruleId,
    severity: p.severity,
    file: sanitizeText(p.file),
    line: p.line,
    // `category` is from a closed allowlist (never parser-supplied text), so it is
    // emitted as-is; the file path is still sanitized because it comes from input.
    category: p.category,
  };
}

// Deterministic, human/CI JSON report. Incomplete scans surface here as both the
// `complete` flag and the parseFailures / skip tallies, so JSON consumers get the
// full diagnostic picture even though SARIF carries them in notifications.
export function formatJson(report: ScanReport): string {
  const payload = {
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    complete: report.complete,
    summary: summarize(report),
    findings: report.result.findings.map(emitFinding),
    parseFailures: report.result.parseFailures.map(emitParseFailure),
    skipped: report.skipped.map((s) => ({
      path: sanitizeText(s.path),
      reason: s.reason,
    })),
  };
  return `${JSON.stringify(payload, null, 2)}\n`;
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

function parseFailureNotification(p: ParseFailure): Record<string, unknown> {
  return {
    descriptor: { id: "supa-scan/parse-failure" },
    level: "error",
    message: { text: sanitizeText(`${p.file}: ${PARSE_CATEGORY_PHRASE[p.category]}`) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: sanitizeText(p.file), uriBaseId: "%SRCROOT%" },
        },
      },
    ],
  };
}

function skipNotification(report: ScanReport): Record<string, unknown> | null {
  if (report.skippedTotal === 0) return null;
  const tally = SKIP_REASONS.map((r) => `${r}: ${report.skipCounts[r] ?? 0}`).join(", ");
  const sample = report.skipped
    .slice(0, 10)
    .map((s) => `${s.path} (${s.reason})`)
    .join("; ");
  const more = report.skippedTotal > 10 ? `; +${report.skippedTotal - 10} more` : "";
  return {
    descriptor: { id: "supa-scan/file-skipped" },
    level: "warning",
    message: {
      text: sanitizeText(
        `${report.skippedTotal} file(s) skipped (${tally}). Examples: ${sample}${more}`,
      ),
    },
  };
}

// SARIF 2.1.0. Ordinary `results` are findings only, referencing implemented
// rules. An incomplete scan is NOT faked as a finding — it is reported through
// the spec's own channel: runs[].invocations[].toolExecutionNotifications, with
// executionSuccessful:false. Rules the scanner cannot yet fire are excluded from
// the descriptor list, so code scanning never advertises a rule that produces no
// result. No secret values appear (the engine masks them), and every scanned
// string is control/bidi sanitized.
export function toSarif(report: ScanReport): string {
  const rules = implementedRuleIds();
  const ruleIndex = new Map(rules.map((id, i) => [id, i] as const));

  const results = report.result.findings.map((f) => {
    const properties: Record<string, unknown> = {
      "security-severity": SECURITY_SEVERITY[f.severity],
    };
    if (f.object !== undefined) properties.object = sanitizeText(f.object);
    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId),
      level: SARIF_LEVEL[f.severity],
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: sanitizeText(f.file), uriBaseId: "%SRCROOT%" },
            region: { startLine: f.line },
          },
        },
      ],
      message: { text: sanitizeText(`${f.evidence} ${f.remediation}`) },
      properties,
    };
  });

  const failures = report.result.parseFailures;
  const notifications: Record<string, unknown>[] = failures
    .slice(0, NOTIFY_CAP)
    .map(parseFailureNotification);
  if (failures.length > NOTIFY_CAP) {
    notifications.push({
      descriptor: { id: "supa-scan/parse-failure" },
      level: "error",
      message: { text: `+${failures.length - NOTIFY_CAP} further parse failures (see JSON report)` },
    });
  }
  const skip = skipNotification(report);
  if (skip) notifications.push(skip);

  const invocation: Record<string, unknown> = { executionSuccessful: report.complete };
  if (notifications.length > 0) invocation.toolExecutionNotifications = notifications;

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
            rules: rules.map((id) => sarifRule(RULE_METADATA[id])),
          },
        },
        results,
        invocations: [invocation],
      },
    ],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}
