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

// 0.1.4 (cinnabar): discovery-file drift, by address only.
// @ts-ignore plain JS verifier
import { discoveryAddresses, compareDiscovery } from "../verify.mjs";
describe("freshness: discovery (/.well-known/x402) addresses", () => {
  const P = A.pay_to.toLowerCase(), Q = "0x" + "4".repeat(40);
  it("extracts standalone addresses only (JSON values; not URL query params or signature prefixes)", () => {
    expect(discoveryAddresses(JSON.stringify({ payTo: A.pay_to, resources: [`https://x.test/q?pool=${Q}`], ownershipProofs: ["0x" + "ab".repeat(65)] }))).toEqual([P]);
    expect(discoveryAddresses(`payTo: ${A.pay_to}\nsee https://x.test/?a=${Q}`)).toEqual([P]);
  });
  it("is stale only on a conflict; a changed list that still holds the live payTo is informational", () => {
    const rep = { freshness: { discovery_pay_tos: [P] } };
    expect(compareDiscovery(rep, [P], [P])).toMatchObject({ comparable: true, conflict: false, changed: false, stale: false });
    expect(compareDiscovery(rep, [P, Q], [P])).toMatchObject({ conflict: false, changed: true, stale: false });
    expect(compareDiscovery(rep, [Q], [P])).toMatchObject({ conflict: true, stale: true });
    expect(compareDiscovery(rep, [], [P])).toMatchObject({ conflict: false, changed: true, stale: false });
    expect(compareDiscovery(rep, null, [P]).comparable).toBe(false);
    expect(compareDiscovery({}, [P], [P])).toMatchObject({ comparable: true, changed: null, stale: false });
  });
});

// 0.1.5: per-invoice amounts (parley), unreadable discovery = unknown (cinnabar), fail-closed state (overwatch-dominion).
// @ts-ignore plain JS verifier
import { amountDrift, liveState } from "../verify.mjs";
import { payeeFingerprint, discoveryStatus } from "../src/check";
describe("freshness 0.1.5", () => {
  const P = A.pay_to.toLowerCase();
  it("per-invoice dust amounts are not drift; a real price change or new payee still is", async () => {
    const base = { ...A, amount: "996138" };
    const report = { checked_at: "2026-10-29T12:00:00Z", freshness: { terms_fingerprint: { hex: await tsFp([base]) }, terms: termsList([base]), amount_tolerance_bps: 100, suggested_max_age_hours: 24 } };
    const now = new Date("2026-10-29T13:00:00Z");
    const jitter = compareFreshness(report, [wire({ ...A, amount: "996076" })], now);
    expect(jitter).toMatchObject({ terms_match: false, stale: false, amount_drift: { payee_match: true, within_tolerance: true } });
    expect(jitter.amount_drift.max_amount_drift_bps).toBeCloseTo(0.62, 1);
    expect(compareFreshness(report, [wire({ ...A, amount: "1100000" })], now)).toMatchObject({ stale: true, amount_drift: { payee_match: true, within_tolerance: false } });
    expect(compareFreshness(report, [wire({ ...A, amount: "996076", pay_to: "0x" + "5".repeat(40) })], now)).toMatchObject({ stale: true, amount_drift: { payee_match: false } });
    // reports from before 0.1.5 have no terms list: any amount change stays stale
    const old = { ...report, freshness: { ...report.freshness, terms: undefined } };
    expect(compareFreshness(old, [wire({ ...A, amount: "996076" })], now).stale).toBe(true);
    expect(amountDrift(termsList([{ ...A, amount: "10" }, B]), termsList([{ ...A, amount: "10" }, B]))).toMatchObject({ payee_match: true, max_amount_drift_bps: 0 });
    expect(await payeeFingerprint([base])).toBe(await payeeFingerprint([{ ...A, amount: "1" }]));
  });
  it("an unreadable or vanished discovery file is unknown, not fresh", () => {
    const rep = { freshness: { discovery_pay_tos: [P] } };
    expect(compareDiscovery(rep, null, [P], "unreadable", "HTTP 503")).toMatchObject({ comparable: false, unknown: true, stale: false });
    expect(compareDiscovery(rep, null, [P], "absent")).toMatchObject({ unknown: true });
    expect(compareDiscovery({ freshness: { discovery_pay_tos: [] } }, null, [P], "absent").unknown).toBeUndefined();
    expect(discoveryStatus({ probes: { well_known_x402: 200 } })).toBe("read");
    expect(discoveryStatus({ probes: { well_known_x402: 404 } })).toBe("absent");
    expect(discoveryStatus({ probes: { well_known_x402: 503 } })).toBe("unreadable");
    expect(discoveryStatus({ probes: { well_known_x402: null } })).toBe("unreadable");
    expect(discoveryStatus({ probes: {} })).toBe("unknown");
    expect(discoveryStatus({ error: "x" })).toBe("unknown");
    // known asset contracts are not payTo candidates (verify.mjs used to list USDC itself)
    expect(discoveryAddresses(JSON.stringify({ asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: A.pay_to }))).toEqual([P]);
  });
  it("state: stale beats unknown; anything unconfirmed is unknown", () => {
    expect(liveState({ freshness: { comparable: true, stale: false }, discovery: { comparable: true, stale: false } })).toBe("fresh");
    expect(liveState({ freshness: { comparable: true, stale: true }, discovery: { unknown: true } })).toBe("stale");
    expect(liveState({ freshness: { comparable: true, stale: false }, discovery: { unknown: true } })).toBe("unknown");
    expect(liveState({ freshness: { comparable: false } })).toBe("unknown");
  });
});
