import { describe, it, expect } from "vitest";
import { termsFingerprint as tsFp, termsList } from "../src/check";
// @ts-ignore plain JS verifier
import { termsFingerprint as jsFp, compareFreshness, acceptsFrom } from "../verify.mjs";

const A = { scheme: "exact", network: "eip155:8453", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", pay_to: "0x15fC1c760dD0DfA6159aB08756C656C7198a428B", amount: "10000", max_timeout_seconds: 300 };
const B = { ...A, network: "eip155:137", asset: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359" };
// The same terms as the live wire format (v2 camelCase payTo), which is what verify.mjs --live sees.
const wire = (x: any) => ({ scheme: x.scheme, network: x.network, asset: x.asset, payTo: x.pay_to, amount: x.amount, maxTimeoutSeconds: 60 });

describe("freshness: payment-terms fingerprint", () => {
  it("is order-independent, case-insensitive on addresses, ignores timeouts, and identical in the Worker and in verify.mjs", async () => {
    const h = await tsFp([A, B]);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(await tsFp([B, A])).toBe(h);
    expect(await tsFp([{ ...A, pay_to: A.pay_to.toLowerCase(), max_timeout_seconds: 9 }, B])).toBe(h);
    expect(jsFp([wire(B), wire(A)])).toBe(h);
    expect(termsList([A]).map((t) => t.pay_to)).toEqual([A.pay_to.toLowerCase()]);
  });
  it("changes when payTo, price or asset changes", async () => {
    const h = await tsFp([A]);
    expect(await tsFp([{ ...A, pay_to: "0x" + "1".repeat(40) }])).not.toBe(h);
    expect(await tsFp([{ ...A, amount: "20000" }])).not.toBe(h);
    expect(await tsFp([{ ...A, asset: "0x" + "2".repeat(40) }])).not.toBe(h);
  });
  it("compareFreshness flags a rotated payTo and an old report, and parses the v2 header", async () => {
    const report = { checked_at: "2026-10-28T00:00:00Z", freshness: { terms_fingerprint: { hex: await tsFp([A]) }, suggested_max_age_hours: 24 } };
    const now = new Date("2026-10-28T02:00:00Z");
    expect(compareFreshness(report, [wire(A)], now)).toMatchObject({ comparable: true, terms_match: true, stale: false, age_hours: 2 });
    const rotated = compareFreshness(report, [wire({ ...A, pay_to: "0x" + "3".repeat(40) })], now);
    expect(rotated).toMatchObject({ terms_match: false, stale: true });
    expect(compareFreshness(report, [wire(A)], new Date("2026-10-30T00:00:00Z"))).toMatchObject({ terms_match: true, stale: true });
    expect(compareFreshness({ checked_at: "2026-10-28T00:00:00Z" }, [wire(A)], now).comparable).toBe(false);
    const hdr = Buffer.from(JSON.stringify({ x402Version: 2, accepts: [wire(A)] })).toString("base64");
    expect(acceptsFrom(new Headers({ "payment-required": hdr }), "")).toHaveLength(1);
    expect(acceptsFrom(new Headers(), JSON.stringify({ accepts: [wire(A), wire(B)] }))).toHaveLength(2);
  });
});
