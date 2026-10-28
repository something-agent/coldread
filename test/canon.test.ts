import { describe, it, expect } from "vitest";
import { canonicalize, sha256Hex } from "../src/canon";
// @ts-ignore plain JS module
import { canonicalize as canonJs } from "../verify.mjs";

describe("JCS (RFC 8785)", () => {
  it("sorts keys by UTF-16 code units, recursively, with no whitespace", () => {
    expect(canonicalize({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: null } })).toBe('{"a":{"c":null,"d":[3,{"y":2,"z":1}]},"b":1}');
    // RFC 8785 3.2.3 sorting example (subset): "\u20ac" > "\r" > "1" ordering by code unit
    expect(canonicalize({ "\u20ac": 1, "\r": 2, "1": 3, "\u0080": 4, "\ud83d\ude00": 5, "\u00f6": 6 })).toBe('{"\\r":2,"1":3,"\u0080":4,"\u00f6":6,"\u20ac":1,"\ud83d\ude00":5}');
  });
  it("serialises numbers the ECMAScript way", () => {
    expect(canonicalize([1e21, 1e-7, -0, 0.1, 100, 333333333.3333333, 4.5e-322])).toBe("[1e+21,1e-7,0,0.1,100,333333333.3333333,4.5e-322]");
    expect(() => canonicalize(NaN)).toThrow();
    expect(() => canonicalize(Infinity)).toThrow();
  });
  it("escapes strings minimally and drops undefined members", () => {
    expect(canonicalize({ s: "a\"b\\c\n\u0001é", u: undefined })).toBe('{"s":"a\\"b\\\\c\\n\\u0001é"}');
  });
  it("the verify script's copy is byte-identical", () => {
    const v = { z: [1, 2.5, "x", null, true, { b: [], a: {} }], "é": -0.0001, a: "\u2028" };
    expect(canonJs(v)).toBe(canonicalize(v));
  });
  it("sha256 hex", async () => {
    expect(await sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});
