import { describe, expect, it } from "vitest";
import { sanitizeText } from "../../src/cli/escape";

// Helpers built from code points so this test file itself carries no raw control
// or invisible bytes, and so the visible escape (a literal backslash + "uXXXX")
// can be compared without embedding a backslash in a way a JSON layer would mangle.
const BS = String.fromCharCode(0x5c); // the backslash of \uXXXX
function visible(code: number): string {
  return `${BS}u${code.toString(16).padStart(4, "0")}`;
}

const ESC = String.fromCharCode(0x1b);
const RLO = String.fromCharCode(0x202e); // right-to-left override
const LRI = String.fromCharCode(0x2066); // left-to-right isolate
const ZWSP = String.fromCharCode(0x200b); // zero-width space
const ZWJ = String.fromCharCode(0x200d); // zero-width joiner
const BOM = String.fromCharCode(0xfeff); // zero-width no-break space / BOM

describe("sanitizeText — control codes are dropped", () => {
  it("leaves ordinary printable text untouched", () => {
    expect(sanitizeText("ALTER TABLE public.todos ENABLE RLS")).toBe(
      "ALTER TABLE public.todos ENABLE RLS",
    );
  });

  it("removes the ESC initiator so a CSI sequence cannot drive the terminal", () => {
    const stripped = sanitizeText(`safe${ESC}[31mRED${ESC}[0m`);
    expect(stripped).toBe("safe[31mRED[0m");
    expect(stripped).not.toContain(ESC);
  });

  it("removes NUL, BEL, newline and tab", () => {
    expect(sanitizeText(`a${BEL()}b${String.fromCharCode(0)}c${String.fromCharCode(10)}d`)).toBe(
      "abcd",
    );
    function BEL() {
      return String.fromCharCode(7);
    }
  });
});

describe("sanitizeText — invisible formatting is escaped visibly, not hidden", () => {
  it("escapes a right-to-left override rather than dropping it silently", () => {
    expect(sanitizeText(`a${RLO}b`)).toBe(`a${visible(0x202e)}b`);
    expect(sanitizeText(`a${RLO}b`)).toContain("202e");
  });

  it("escapes bidi isolates", () => {
    expect(sanitizeText(`x${LRI}y`)).toBe(`x${visible(0x2066)}y`);
  });

  it("escapes zero-width characters and the BOM", () => {
    expect(sanitizeText(`a${ZWSP}b`)).toBe(`a${visible(0x200b)}b`);
    expect(sanitizeText(`a${ZWJ}b`)).toBe(`a${visible(0x200d)}b`);
    expect(sanitizeText(`${BOM}hi`)).toBe(`${visible(0xfeff)}hi`);
  });

  it("mixes dropping and escaping correctly on adversarial input", () => {
    const evil = `${ESC}[0m${RLO}pay${ZWSP}${BOM}`;
    const out = sanitizeText(evil);
    expect(out).not.toContain(ESC);
    expect(out).not.toContain(RLO);
    expect(out).not.toContain(ZWSP);
    expect(out).not.toContain(BOM);
    // The visible markers remain as inert text.
    expect(out).toContain(visible(0x202e));
    expect(out).toContain("pay");
  });
});
