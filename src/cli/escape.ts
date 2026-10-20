// Text originating from the scanned repo (evidence, object names, file paths,
// parse messages) is attacker-controlled. Two distinct risks, two treatments:
//
//  1. Control codes (C0 U+0000-U+001F, DEL U+007F, C1 U+0080-U+009F) — these are
//     never legitimate printable text and can drive a terminal (ANSI/CSI/OSC). We
//     DROP them. Removing the ESC initiator in particular neutralizes escape
//     sequences. (Same lesson as soar-pending.)
//  2. Invisible directional / zero-width formatting characters — right-to-left
//     overrides and isolates (U+202A-U+202E, U+2066-U+2069), directional marks,
//     zero-width joiners/spaces and the BOM. Dropping these silently is exactly
//     the danger: they let crafted text reorder or hide characters so a human
//     reads something misleading. We escape them VISIBLY as \uXXXX so a reviewer
//     sees the anomaly instead of being spoofed by it.
//
// Code points are compared as integers and the escape is written with an escaped
// backslash, so this source file contains no raw control or invisible bytes.

const C0_MAX = 0x1f;
const DEL = 0x7f;
const C1_MAX = 0x9f;

// Format-control and zero-width characters whose presence can mislead a reader.
const INVISIBLE = new Set<number>([
  0x200b, // zero-width space
  0x200c, // zero-width non-joiner
  0x200d, // zero-width joiner
  0x200e, // left-to-right mark
  0x200f, // right-to-left mark
  0x202a, // left-to-right embedding
  0x202b, // right-to-left embedding
  0x202c, // pop directional formatting
  0x202d, // left-to-right override
  0x202e, // right-to-left override
  0x2060, // word joiner
  0x2061, // function application
  0x2062, // invisible times
  0x2063, // invisible separator
  0x2064, // invisible plus
  0x2066, // left-to-right isolate
  0x2067, // right-to-left isolate
  0x2068, // first strong isolate
  0x2069, // pop directional isolate
  0xfeff, // zero-width no-break space / BOM
]);

function escapeCodePoint(code: number): string {
  return `\\u${code.toString(16).padStart(4, "0")}`;
}

export function sanitizeText(input: string): string {
  let out = "";
  for (const char of input) {
    const code = char.codePointAt(0);
    if (code === undefined) continue;
    if (code <= C0_MAX) continue; // C0 controls: dropped
    if (code >= DEL && code <= C1_MAX) continue; // DEL + C1 controls: dropped
    if (INVISIBLE.has(code)) {
      out += escapeCodePoint(code); // invisible formatting: shown, not hidden
      continue;
    }
    out += char;
  }
  return out;
}
