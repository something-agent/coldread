import { describe, it, expect } from "vitest";
import { payerSummary, WINDOW_BLOCKS, LOOKBACK_BLOCKS } from "../src/payers";
import { stubFetch, fakeRpc, json, PAYTO } from "./helpers";

const HEAD = 40_000_000;
const SWEEPER = "0xa1d1c0cf717402ff3651aa4873ccf96410b01978";
const BROAD = "0x00000000000000000000000000000000000b0a0d";
const BUYER = "0x00000000000000000000000000000000000b0b0b";
const addr = (i: number) => "0x" + i.toString(16).padStart(40, "0");

function world() {
  const t: { from: string; to: string; usdc: number; block: number }[] = [];
  t.push({ from: PAYTO, to: PAYTO, usdc: 0.01, block: HEAD - 10 });            // self
  t.push({ from: SWEEPER, to: PAYTO, usdc: 0.001, block: HEAD - 20_000 });     // documented sweeper
  for (let i = 0; i < 3; i++) t.push({ from: BUYER, to: PAYTO, usdc: 0.02, block: HEAD - 100 - i }); // repeat buyer
  t.push({ from: BROAD, to: PAYTO, usdc: 0.01, block: HEAD - 5 });
  t.push({ from: BROAD, to: PAYTO, usdc: 0.01, block: HEAD - 6 });
  for (let i = 1; i <= 25; i++) t.push({ from: BROAD, to: addr(1000 + i), usdc: 0.01, block: HEAD - 1000 - i }); // pays 25 others
  t.push({ from: BUYER, to: addr(77), usdc: 1, block: HEAD - 50 });
  t.push({ from: addr(9), to: PAYTO, usdc: 5, block: HEAD - WINDOW_BLOCKS - 5 }); // outside the window
  return t;
}

describe("payer summary", () => {
  it("counts the window and labels self, known sweeper, broad payer and repeat buyer", async () => {
    const { f, calls } = stubFetch([fakeRpc({ head: HEAD, transfers: world() })]);
    const s: any = await payerSummary([PAYTO], f);
    expect(s.status).toBe("ok");
    expect(s.window).toMatchObject({ from_block: HEAD - WINDOW_BLOCKS + 1, to_block: HEAD, blocks: 50_000, approx_hours: 27.8 });
    expect(s.inbound.transfers).toBe(7);
    expect(s.inbound.distinct_payers).toBe(4);
    expect(s.self_payments.transfers).toBe(1);
    const by = Object.fromEntries(s.payers.map((p: any) => [p.address, p.label]));
    expect(by).toEqual({ [BUYER]: "repeat_or_narrow", [BROAD]: "broad_payer", [PAYTO]: "self", [SWEEPER]: "known_sweeper" });
    expect(s.by_label.repeat_or_narrow.transfers).toBe(3);
    expect(s.top_payer_share).toBeCloseTo(3 / 7, 3);
    // BUYER: 3 transfers within 3 blocks = burst; BROAD: 2 within 1 block = burst; self excluded
    expect(s.repeats).toMatchObject({ payers: 3, with_2plus_transfers: 2, burst_only: 2, returned_after_1h: 0 });
    expect(s.limits.join(" ")).toMatch(/recent window only/);
    // 3 RPC calls only: block number, one inbound batch, one classification batch
    expect(calls.length).toBe(3);
    const batch = JSON.parse(calls[1].body!);
    expect(batch.length).toBe(5);
    expect(JSON.parse(calls[2].body!).length).toBe(2 * (LOOKBACK_BLOCKS / 10_000)); // two payers to classify
  });
  it("splits repeat payers into bursts and payers that came back more than ~1 h later", async () => {
    const t = [
      { from: BUYER, to: PAYTO, usdc: 0.01, block: HEAD - 30_000 }, { from: BUYER, to: PAYTO, usdc: 0.01, block: HEAD - 100 }, // came back ~16 h later
      { from: addr(5), to: PAYTO, usdc: 0.01, block: HEAD - 2000 }, { from: addr(5), to: PAYTO, usdc: 0.01, block: HEAD - 1000 }, // 1000 blocks apart = burst
      { from: addr(6), to: PAYTO, usdc: 0.01, block: HEAD - 7 },
    ];
    const { f } = stubFetch([fakeRpc({ head: HEAD, transfers: t })]);
    const s: any = await payerSummary([PAYTO], f);
    expect(s.repeats).toMatchObject({ payers: 3, with_2plus_transfers: 2, burst_only: 1, returned_after_1h: 1 });
  });
  it("not_applicable without a Base USDC payTo, and makes no calls", async () => {
    const { f, calls } = stubFetch([]);
    expect((await payerSummary([], f) as any).status).toBe("not_applicable");
    expect(calls.length).toBe(0);
  });
  it("retries a 429 from the RPC, then succeeds; refused log queries throw with the provider's reason", async () => {
    let n = 0;
    const rpc = fakeRpc({ head: HEAD, transfers: [] });
    const { f, calls } = stubFetch([(u, i) => (u.includes("publicnode") && n++ === 0 ? json({ error: "rate limit" }, 429) : rpc(u, i))]);
    const s: any = await payerSummary([PAYTO], f);
    expect(s.status).toBe("ok");
    expect(s.window.rpc).toBe("base-rpc.publicnode.com");
    expect(calls.length).toBe(3); // 429, retry of eth_blockNumber, one getLogs batch (no payers to classify)
    const { f: f2 } = stubFetch([fakeRpc({ head: HEAD, failLogs: true })]);
    await expect(payerSummary([PAYTO], f2)).rejects.toThrow(/publicnode.*exceed max block range/);
    const { f: f3 } = stubFetch([(u) => json({ error: "x" }, 503)]);
    await expect(payerSummary([PAYTO], f3)).rejects.toThrow(/http 503/);
  }, 15_000);
});
