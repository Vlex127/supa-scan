// Bounded, non-revealing text helpers for the source (secret) rules.
//
// The engine never echoes a secret. Evidence carries the *claim* (the matched
// format, the variable NAME, the role), the line number (the Finding.line), and a
// LENGTH — but not any slice of a credential value. A masked value that still
// reveals the first or last characters is a partial leak, so these helpers emit
// lengths only, never prefixes of high-entropy material.

// A single source line longer than this is anomalous (generated, data-URL, a
// minified bundle that slipped past scope). We skip pattern matching on it: the
// regex stays linear-bounded and we never spend unbounded time on one hostile line.
export const MAX_LINE_LEN = 2000;

// Names we put in `object` come from scanned text; bound them so a crafted long
// identifier can never inflate the report.
export const MAX_NAME_LEN = 120;

export function clipName(name: string): string {
  return name.length <= MAX_NAME_LEN ? name : `${name.slice(0, MAX_NAME_LEN)}…`;
}

// A value's length, phrased for evidence. The value itself is never included.
export function describeLength(value: string): string {
  return `${value.length}-character value`;
}

export interface ScannedLine {
  line: number; // 1-based
  text: string;
  // True when the raw line exceeded MAX_LINE_LEN and `text` was left empty. Rules
  // must skip matching on these but the file as a whole still counts as analyzed.
  skipped: boolean;
}

// Split content into 1-based lines for matching. Over-long lines are returned with
// an empty, `skipped`-marked body so callers do not regex them, while normal lines
// keep their exact text and a trailing CR is trimmed (Windows CRLF).
export function scanLines(content: string): ScannedLine[] {
  const raw = content.split("\n");
  const out: ScannedLine[] = [];
  for (let idx = 0; idx < raw.length; idx++) {
    let text = raw[idx];
    if (text.endsWith("\r")) text = text.slice(0, -1);
    if (text.length > MAX_LINE_LEN) {
      out.push({ line: idx + 1, text: "", skipped: true });
    } else {
      out.push({ line: idx + 1, text, skipped: false });
    }
  }
  return out;
}
