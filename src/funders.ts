/** Funder clustering (box batch job only; 0.1.7, asked by northtape on The Colony).
 *  For each top non-self payer: the earliest inbound USDC transfer to it in the last FUNDER_WINDOW blocks is its
 *  "funder". Payers that share a funder AND were funded within BURST_BLOCKS of each other collapse into one cluster.
 *  A funder that sends USDC to HUB_FANOUT+ different addresses in HUB_LOOKBACK blocks (or whose outbound logs are too
 *  big to read) is a hub (exchange hot wallet, bridge, faucet) and never collapses anyone: it groups strangers.
 *  Clusters are hypotheses. Limits: USDC only (ETH gas funding needs a tracer), window-bound, inbound only. */
import { rpcBatch, BASE_USDC, BURST_BLOCKS } from "./payers";

const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CHUNK = 10_000;
export const FUNDER_WINDOW = 50_000;
export const HUB_LOOKBACK = 20_000;
export const HUB_FANOUT = 10;
export const MAX_PAYERS = 10;
const pad = (a: string) => "0x" + a.slice(2).toLowerCase().padStart(64, "0");
const addrOf = (t: string) => "0x" + t.slice(-40).toLowerCase();

export interface Funding { payer: string; funder: string | null; block: number; usdc: number }
export interface Cluster { funder: string; payers: string[]; blocks: number[]; usdc: number[] }

/** Pure: group fundings by shared non-hub funder, chaining fundings no more than `gap` blocks apart. */
export function clusterFundings(fs: Funding[], hubs: Set<string>, gap = BURST_BLOCKS): Cluster[] {
  const by = new Map<string, Funding[]>();
  for (const f of fs) if (f.funder && !hubs.has(f.funder)) by.set(f.funder, [...(by.get(f.funder) ?? []), f]);
  const out: Cluster[] = [];
  for (const [funder, list] of by) {
    list.sort((a, b) => a.block - b.block);
    let cur: Funding[] = [];
    const flush = () => { if (new Set(cur.map((x) => x.payer)).size >= 2) out.push({ funder, payers: cur.map((x) => x.payer), blocks: cur.map((x) => x.block), usdc: cur.map((x) => x.usdc) }); cur = []; };
    for (const f of list) { if (cur.length && f.block - cur[cur.length - 1].block > gap) flush(); cur.push(f); }
    flush();
  }
  return out;
}

const ranges = (from: number, head: number) => { const r: [number, number][] = []; for (let s = from; s <= head; s += CHUNK) r.push([s, Math.min(s + CHUNK - 1, head)]); return r; };
const hex = (n: number) => "0x" + n.toString(16);

export async function funderClusters(payers: string[], payTos: string[], fetchImpl: typeof fetch) {
  const pts = payTos.map((p) => p.toLowerCase());
  const list = payers.map((p) => p.toLowerCase()).filter((p) => !pts.includes(p)).slice(0, MAX_PAYERS);
  const head = parseInt((await rpcBatch([{ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }], fetchImpl, 8000)).results[0].result, 16);
  const fundings: Funding[] = [], errors: string[] = [];
  for (const p of list) {
    try {
      const calls = ranges(head - FUNDER_WINDOW + 1, head).map(([a, b], i) => ({ jsonrpc: "2.0", id: i + 1, method: "eth_getLogs", params: [{ address: BASE_USDC, topics: [TRANSFER, null, pad(p)], fromBlock: hex(a), toBlock: hex(b) }] }));
      const logs = (await rpcBatch(calls, fetchImpl)).results.flatMap((r) => r.result ?? []).filter((l: any) => !pts.includes(addrOf(l.topics[1])) && addrOf(l.topics[1]) !== p);
      logs.sort((x: any, y: any) => parseInt(x.blockNumber, 16) - parseInt(y.blockNumber, 16));
      const l = logs[0];
      fundings.push(l ? { payer: p, funder: addrOf(l.topics[1]), block: parseInt(l.blockNumber, 16), usdc: Number(BigInt(l.data === "0x" ? 0 : l.data)) / 1e6 } : { payer: p, funder: null, block: 0, usdc: 0 });
    } catch (e) { errors.push(`${p}: ${(e as Error).message.slice(0, 100)}`); }
  }
  const hubs = new Set<string>();
  const shared = [...new Set(fundings.map((f) => f.funder).filter((f): f is string => !!f && fundings.filter((g) => g.funder === f).length >= 2))];
  for (const f of shared) {
    try {
      const calls = ranges(head - HUB_LOOKBACK + 1, head).map(([a, b], i) => ({ jsonrpc: "2.0", id: i + 1, method: "eth_getLogs", params: [{ address: BASE_USDC, topics: [TRANSFER, pad(f)], fromBlock: hex(a), toBlock: hex(b) }] }));
      const to = new Set((await rpcBatch(calls, fetchImpl)).results.flatMap((r) => r.result ?? []).map((l: any) => addrOf(l.topics[2])));
      if (to.size >= HUB_FANOUT) hubs.add(f);
    } catch { hubs.add(f); }
  }
  return {
    method: `earliest inbound USDC transfer per payer in the last ${FUNDER_WINDOW} blocks; payers sharing a non-hub funder within ${BURST_BLOCKS} blocks are one cluster (hypothesis)`,
    head, payers_checked: fundings.length, no_usdc_funder_in_window: fundings.filter((f) => !f.funder).length,
    hubs_excluded: [...hubs], clusters: clusterFundings(fundings, hubs), fundings, ...(errors.length ? { errors } : {}),
    limits: ["USDC only; native ETH (gas) funding is not traced", "funding before the window is invisible", "inbound only; shared outbound deposit addresses are not checked yet"],
  };
}
