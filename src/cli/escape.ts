// Text originating from the scanned repo (evidence, object names, file paths,
// parse messages) is attacker-controlled. A malicious SQL comment or identifier
// could carry terminal control sequences (e.g. ANSI escapes) that, printed raw,
// would corrupt or impersonate the terminal — the same lesson as soar-pending.
// Strip C0 controls (U+0000-U+001F), DEL (U+007F) and C1 controls (U+0080-U+009F)
// before any scanned string is emitted. Printable text is unaffected; newlines
// and tabs are removed too, which is correct for single-line evidence and keeps
// serialized output clean. We compare code points rather than using a control
// character class so the source itself never contains raw control bytes.
export function stripControl(input: string): string {
  let out = "";
  for (const char of input) {
    const code = char.codePointAt(0);
    if (code === undefined) continue;
    if (code <= 0x1f) continue; // C0: NUL..Unit Separator (includes ESC, BEL, LF, TAB)
    if (code >= 0x7f && code <= 0x9f) continue; // DEL + C1
    out += char;
  }
  return out;
}
