import { describe, expect, it } from "vitest";
import { stripControl } from "../../src/cli/escape";

const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const NUL = String.fromCharCode(0x00);
const LF = String.fromCharCode(0x0a);
const TAB = String.fromCharCode(0x09);
const C1 = String.fromCharCode(0x85); // NEXT LINE, a C1 control

describe("stripControl", () => {
  it("leaves ordinary printable text untouched", () => {
    expect(stripControl("ALTER TABLE public.todos ENABLE RLS")).toBe(
      "ALTER TABLE public.todos ENABLE RLS",
    );
  });

  it("removes the ESC initiator so a CSI sequence cannot drive the terminal", () => {
    const tainted = `safe${ESC}[31mRED${ESC}[0m`;
    const stripped = stripControl(tainted);
    // The ESC control codes are gone; without them the sequence never starts, so
    // the remaining [31m / [0m are inert literal text, not colour codes.
    expect(stripped).toBe("safe[31mRED[0m");
    expect(stripped).not.toContain(ESC);
  });

  it("removes NUL, BEL, newline and tab (single-line evidence)", () => {
    expect(stripControl(`a${BEL}b${NUL}c${LF}d${TAB}e`)).toBe("abcde");
  });

  it("removes C1 controls", () => {
    expect(stripControl(`x${C1}y`)).toBe("xy");
  });

  it("returns an empty string for all-control input", () => {
    expect(stripControl(`${BEL}${ESC}${NUL}`)).toBe("");
  });
});
