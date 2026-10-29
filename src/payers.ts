/** Labelled payer summary for a Base USDC payTo, over a stated recent window, from public RPC logs only.
 *  Keyless public RPCs cap eth_getLogs at 50,000 blocks (publicnode; others refuse or allow 50 blocks, tested
 *  2026-10-28), so this is a recent-window view, never full history, and the report says so. */
export const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
export const BASE_CAIP2 = "eip155:8453";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
/** Keyless Base RPCs that serve 10,000-block eth_getLogs. Tested 2026-10-28: only publicnode does. drpc's free plan
 *  refuses every getLogs with a null topic ("ranges over 10000 blocks"), blastapi allows 10 blocks, nodies and 1rpc 50,
 *  onfinality/zan/blockpi need keys, Blockscout sits behind a Cloudflare challenge. publicnode rate-limits Cloudflare's
 *  shared egress (HTTP 429), so the Worker retries, then falls back to a box-computed summary (see payer cache). */
export const LOG_RPCS: { url: string; maxBatch: number }[] = [{ url: "https://base-rpc.publicnode.com", maxBatch: 50 }];
const RETRY_MS = [1200, 3000];
export const WINDOW_BLOCKS = 50_000; // ~27.8 h at 2 s blocks
const CHUNK = 10_000;
export const LOOKBACK_BLOCKS = 20_000; // payer-side window used to classify the top payers (~11 h)
export const BURST_BLOCKS = 1800;      // ~1 h of Base blocks: transfers closer than this count as one burst
export const BROAD_PAYEES = 20;       // distinct payees in the lookback that make a payer "broad" (sweeper-like)
const TOP_CLASSIFIED = 3;
const MAX_BYTES = 3_000_000;

/** Addresses ColdRead has itself documented, with the evidence. Labels are hypotheses, not accusations. */
export const KNOWN_PAYERS: Record<string, { label: string; evidence: string }> = {
  "0xa1d1c0cf717402ff3651aa4873ccf96410b01978": { label: "known_sweeper", evidence: "paid 368 distinct payees in Base blocks 53,110,000-53,175,000 with no repeat to the same payee (ColdRead research 2026-10-27)" },
  "0x7722dfae6bbed2fd02dc07455c2f5bf14be25e4a": { label: "known_sweeper", evidence: "paid 74 distinct payees in Base blocks 53,110,000-53,175,000 with no repeat to the same payee (ColdRead research 2026-10-27)" },
};

const pad = (a: string) => "0x" + a.slice(2).toLowerCase().padStart(64, "0");
const addrOf = (topic: string) => "0x" + topic.slice(-40).toLowerCase();

async function post(url: string, body: any[], fetchImpl: typeof fetch, timeoutMs: number): Promise<any[]> {
  const r = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json", "user-agent": "coldread/0.1 (+https://github.com/something-agent/coldread)" }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
  const t = await r.text();
  if (!r.ok) throw new Error(`http ${r.status}${t ? ": " + t.slice(0, 80).replace(/\s+/g, " ") : ""}`);
  if (t.length > MAX_BYTES) throw new Error(`response over ${MAX_BYTES} bytes`);
  const j = JSON.parse(t);
  return Array.isArray(j) ? j : [j];
}

/** One JSON-RPC batch (split per provider limit). Tries each provider; a provider is used only if every item succeeds. */
export async function rpcBatch(body: any[], fetchImpl: typeof fetch, timeoutMs = 25_000, retries = true): Promise<{ results: any[]; rpc: string }> {
  const errs: string[] = [];
  for (const p of LOG_RPCS) {
    const host = new URL(p.url).host;
    try {
      const parts: any[][] = [];
      for (let i = 0; i < body.length; i += p.maxBatch) parts.push(body.slice(i, i + p.maxBatch));
      let arr: any[] = [];
      for (let attempt = 0; ; attempt++) {
        try { arr = (await Promise.all(parts.map((b) => post(p.url, b, fetchImpl, timeoutMs)))).flat(); break; }
        catch (e) { if (!/http 429/.test((e as Error).message) || attempt >= RETRY_MS.length || !retries) throw e; await new Promise((r) => setTimeout(r, RETRY_MS[attempt])); }
      }
      const byId = new Map(arr.map((x) => [x.id, x]));
      const results = body.map((b) => byId.get(b.id) ?? { error: { message: "missing response" } });
      const bad = results.find((x) => x.error);
      if (bad) { errs.push(`${host}: ${String(bad.error?.message ?? "error").slice(0, 100)}`); continue; }
      return { results, rpc: host };
    } catch (e) { errs.push(`${host}: ${(e as Error).message.slice(0, 120)}`); }
  }
  throw new Error(errs.join("; "));
}

export interface PayerRow { address: string; transfers: number; usdc: number; label: string; evidence: string }

export async function payerSummary(payTos: string[], fetchImpl: typeof fetch) {
  const pts = [...new Set(payTos.map((p) => p.toLowerCase()))].slice(0, 2);
  const base = {
    chain: BASE_CAIP2, asset: BASE_USDC, pay_to: pts,
    method: "USDC Transfer logs to the payTo over the window (public RPC eth_getLogs). For the top payers by count, their outgoing USDC transfers over a shorter lookback are counted to see how many different payees they pay.",
    labels_meaning: {
      self: "payer is the payTo itself (self-test or keep-alive), never demand",
      known_sweeper: "an address ColdRead has documented paying hundreds of payees once each (catalogue sweeper or crawler)",
      broad_payer: `paid ${BROAD_PAYEES}+ different payees in the lookback window: sweeper-like or an aggregator; not by itself proof of anything`,
      repeat_or_narrow: "not self, not known, paid fewer than the broad threshold of payees: consistent with a chosen buyer, but not proven independent (one operator can run many wallets)",
      unclassified: "outside the top payers we classify per request",
    },
  };
  if (!pts.length) return { status: "not_applicable", detail: "no Base USDC payTo in the live 402 (and none supplied)", ...base };
  const head0 = await rpcBatch([{ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }], fetchImpl, 8000);
  const head = parseInt(head0.results[0].result, 16);
  if (!Number.isFinite(head)) throw new Error("bad block number");
  const from = head - WINDOW_BLOCKS + 1;
  const calls: any[] = [];
  let id = 1;
  for (const p of pts) for (let s = from; s <= head; s += CHUNK) calls.push({ jsonrpc: "2.0", id: id++, method: "eth_getLogs", params: [{ address: BASE_USDC, topics: [TRANSFER, null, pad(p)], fromBlock: "0x" + s.toString(16), toBlock: "0x" + Math.min(s + CHUNK - 1, head).toString(16) }] });
  const { results, rpc } = await rpcBatch(calls, fetchImpl);
  const failed = results.filter((r) => r.error).length;
  const per = new Map<string, { n: number; v: bigint; b0: number; b1: number }>();
  let n = 0, total = 0n, selfN = 0, selfV = 0n;
  for (const r of results) for (const l of (r.result ?? []) as any[]) {
    const fromA = addrOf(l.topics[1]), to = addrOf(l.topics[2]);
    const v = BigInt(l.data === "0x" ? 0 : l.data);
    n++; total += v;
    if (fromA === to || pts.includes(fromA)) { selfN++; selfV += v; }
    const bn = parseInt(l.blockNumber ?? "0x0", 16) || 0;
    const e = per.get(fromA) ?? { n: 0, v: 0n, b0: bn, b1: bn }; e.n++; e.v += v; e.b0 = Math.min(e.b0, bn); e.b1 = Math.max(e.b1, bn); per.set(fromA, e);
  }
  const usd = (v: bigint) => Number(v) / 1e6;
  // Repeat payers, split by timing: a burst (all transfers within ~1 h) can be one session or a retry; a payer that came
  // back after more than ~1 h is the closer thing to a returning buyer. Self-payments excluded.
  const others = [...per.entries()].filter(([a]) => !pts.includes(a));
  const multi = others.filter(([, e]) => e.n > 1);
  const returned = multi.filter(([, e]) => e.b1 - e.b0 > BURST_BLOCKS).length;
  const repeats = { payers: others.length, with_2plus_transfers: multi.length, burst_only: multi.length - returned, returned_after_1h: returned, definition: `with_2plus_transfers counts every non-self payer with 2+ inbound transfers in the window; burst_only = all of them within ${BURST_BLOCKS} blocks (~1 h at 2 s/block), returned_after_1h = first and last more than that apart. Only the window is seen, so a buyer returning across days is undercounted.` };
  const sorted = [...per.entries()].sort((a, b) => b[1].n - a[1].n || (b[1].v > a[1].v ? 1 : -1));
  const rows: PayerRow[] = sorted.map(([a, e]) => ({ address: a, transfers: e.n, usdc: usd(e.v), label: "unclassified", evidence: "" }));
  // classify the top payers
  const toCheck = rows.filter((r) => !pts.includes(r.address) && !KNOWN_PAYERS[r.address]).slice(0, TOP_CLASSIFIED);
  for (const r of rows) {
    if (pts.includes(r.address)) { r.label = "self"; r.evidence = "payer equals the payTo"; }
    else if (KNOWN_PAYERS[r.address]) { r.label = KNOWN_PAYERS[r.address].label; r.evidence = KNOWN_PAYERS[r.address].evidence; }
  }
  let classifyNote: string | undefined;
  if (toCheck.length) {
    const lbFrom = head - LOOKBACK_BLOCKS + 1;
    const c2: any[] = [];
    let j = 1;
    for (const r of toCheck) for (let s = lbFrom; s <= head; s += CHUNK) c2.push({ jsonrpc: "2.0", id: j++, method: "eth_getLogs", params: [{ address: BASE_USDC, topics: [TRANSFER, pad(r.address)], fromBlock: "0x" + s.toString(16), toBlock: "0x" + Math.min(s + CHUNK - 1, head).toString(16) }] });
    try {
      const { results: res2 } = await rpcBatch(c2, fetchImpl);
      const perChunks = Math.ceil(LOOKBACK_BLOCKS / CHUNK);
      toCheck.forEach((r, i) => {
        const part = res2.slice(i * perChunks, (i + 1) * perChunks);
        if (part.some((x) => x.error)) { r.evidence = "lookback query failed; left unclassified"; return; }
        const payees = new Set<string>(); let outN = 0;
        for (const x of part) for (const l of x.result as any[]) { payees.add(addrOf(l.topics[2])); outN++; }
        if (payees.size >= BROAD_PAYEES) { r.label = "broad_payer"; r.evidence = `${outN} outgoing USDC transfers to ${payees.size} different payees in the last ${LOOKBACK_BLOCKS.toLocaleString("en-US")} blocks`; }
        else { r.label = "repeat_or_narrow"; r.evidence = `${outN} outgoing USDC transfers to ${payees.size} different payee(s) in the last ${LOOKBACK_BLOCKS.toLocaleString("en-US")} blocks`; }
      });
    } catch (e) {
      classifyNote = `payer classification failed: ${(e as Error).message.slice(0, 160)}`;
      for (const r of toCheck) r.evidence = "classification query failed (RPC); left unclassified";
    }
  }
  const sumBy = (lab: string) => rows.filter((r) => r.label === lab).reduce((a, r) => ({ transfers: a.transfers + r.transfers, usdc: +(a.usdc + r.usdc).toFixed(6) }), { transfers: 0, usdc: 0 });
  const top = rows[0];
  return {
    status: failed ? (failed === results.length ? "rpc_error" : "partial") : "ok",
    ...base,
    window: { from_block: from, to_block: head, blocks: WINDOW_BLOCKS, approx_hours: Math.round((WINDOW_BLOCKS * 2) / 360) / 10, failed_chunks: failed, rpc },
    lookback_blocks_for_classification: LOOKBACK_BLOCKS,
    inbound: { transfers: n, usdc: usd(total), distinct_payers: rows.length },
    self_payments: { transfers: selfN, usdc: usd(selfV) },
    repeats,
    top_payer_share: top && n ? +(top.transfers / n).toFixed(3) : null,
    by_label: { self: sumBy("self"), known_sweeper: sumBy("known_sweeper"), broad_payer: sumBy("broad_payer"), repeat_or_narrow: sumBy("repeat_or_narrow"), unclassified: sumBy("unclassified") },
    payers: rows.slice(0, 10),
    ...(rows.length > 10 ? { payers_truncated: rows.length - 10 } : {}),
    ...(classifyNote ? { note: classifyNote } : {}),
    limits: [
      `recent window only (${WINDOW_BLOCKS.toLocaleString("en-US")} Base blocks, about 28 hours); older history is not read`,
      "only USDC on Base; other networks in accepts[] are not summarised",
      "labels are hypotheses from transfer patterns; one operator can control many wallets, and exchange-funded wallets look independent",
      "a transfer to the payTo is not proof that it paid for this route (the payTo may serve several routes or receive other funds)",
    ],
  };
}
