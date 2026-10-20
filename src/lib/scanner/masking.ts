// Bounded, non-revealing text helpers for the source (secret) rules.
//
// The engine never echoes a secret. Evidence carries the *claim* (the matched
// format, the variable NAME, the role), the line number (the Finding.line), and a
// LENGTH — but not any slice of a credential value. A masked value that still
// reveals the first or last characters is a partial leak, so these helpers emit
// lengths only, never prefixes of high-entropy material.

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

// A source line can be huge (a generated bundle, a data URL, a minified file that
// slipped past scope). We must NOT silently skip such a line — that is a blindable
// evasion path where a credential parked past an arbitrary cut is missed. Instead we
// scan every line, splitting a long one into OVERLAPPING windows. Each window is at
// most CHUNK_WINDOW chars and consecutive windows overlap by CHUNK_OVERLAP, so any
// credential no longer than CHUNK_OVERLAP lies whole inside at least one window and
// can never straddle a boundary unseen. Real Supabase credentials and JWTs are far
// shorter than CHUNK_OVERLAP; the file itself is already size-capped by the
// collector, so the per-char regex work stays linear and bounded.
export const CHUNK_WINDOW = 8192;
export const CHUNK_OVERLAP = 4096;

export interface ScannedChunk {
  line: number; // 1-based line the slice came from
  text: string; // the slice handed to the matchers
}

// Split content into 1-based lines and emit each for matching. A line up to
// CHUNK_WINDOW is emitted whole (so anchored patterns and exact text behave as
// before); a longer line becomes overlapping windows as above. A trailing CR is
// trimmed (Windows CRLF). No line is ever dropped.
export function scanChunks(content: string): ScannedChunk[] {
  const raw = content.split("\n");
  const out: ScannedChunk[] = [];
  for (let idx = 0; idx < raw.length; idx++) {
    let text = raw[idx];
    if (text.endsWith("\r")) text = text.slice(0, -1);
    const line = idx + 1;
    if (text.length <= CHUNK_WINDOW) {
      out.push({ line, text });
      continue;
    }
    const step = CHUNK_WINDOW - CHUNK_OVERLAP; // 4096, strictly positive
    for (let start = 0; ; start += step) {
      out.push({ line, text: text.slice(start, start + CHUNK_WINDOW) });
      if (start + CHUNK_WINDOW >= text.length) break;
    }
  }
  return out;
}
