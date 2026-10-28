import { readFileSync } from "node:fs";
import { join } from "node:path";
import { keccak_256 } from "@noble/hashes/sha3";
export type Route = (url: string, init?: RequestInit) => Response | undefined | Promise<Response | undefined>;
export function stubFetch(routes: Route[]) {
  const calls: { url: string; method: string; body?: string }[] = [];
  const f = (async (input: any, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.url;
    calls.push({ url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : undefined });
    for (const r of routes) { const res = await r(url, init); if (res) return res; }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { f, calls };
}
export const json = (o: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", ...headers } });
export function fixture(name: string, status = 402): Response {
  const h = readFileSync(join(__dirname, "fixtures", name + ".headers"), "utf8").split("\n").slice(1);
  const headers = new Headers();
  for (const line of h) { const i = line.indexOf(":"); if (i > 0) { const k = line.slice(0, i).trim().toLowerCase(); if (!["content-length", "content-encoding", "transfer-encoding", "alt-svc"].includes(k)) headers.set(k, line.slice(i + 1).trim()); } }
  return new Response(readFileSync(join(__dirname, "fixtures", name + ".body")), { status, headers });
}
export const fixtureText = (n: string) => readFileSync(join(__dirname, "fixtures", n), "utf8");
export const CAPTURED = new Date(Number(readFileSync(join(__dirname, "fixtures", "captured_at.txt"), "utf8").trim()) * 1000);
export const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");
export const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const PAYTO = "0x209693bc6afc0c5328ba36faf03c514ef312287c";
export const GOOD_PR = (over: Record<string, any> = {}) => ({
  x402Version: 2,
  resource: { url: "https://api.example.com/data", description: "Example", mimeType: "application/json" },
  accepts: [{ scheme: "exact", network: "eip155:8453", asset: USDC, payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", amount: "10000", maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } }],
  extensions: { bazaar: {} },
  ...over,
});
/** A seller that answers 402 on GET and POST with the given PaymentRequired. */
export const seller = (host: string, pr: any): Route => (url) => {
  const u = new URL(url);
  if (u.hostname !== host) return undefined;
  if (u.pathname === "/data") return json({ error: "payment required" }, 402, { "payment-required": b64(pr) });
  return undefined;
};

const T = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const topicAddr = (a: string) => "0x" + a.slice(2).toLowerCase().padStart(64, "0");
export const sel = (sig: string) => Buffer.from(keccak_256(new TextEncoder().encode(sig)).slice(0, 4)).toString("hex");
const word = (hex: string) => hex.replace(/^0x/, "").padStart(64, "0");
export const abiString = (s: string) => { const b = Buffer.from(s, "utf8").toString("hex"); return "0x" + word("20") + word((b.length / 2).toString(16)) + b.padEnd(Math.ceil(b.length / 64) * 64, "0"); };

/** A fake Base RPC: transfers = [{from,to,usdc,block}], agents = {id: {owner, wallet, uri}}. */
export function fakeRpc(o: { head?: number; transfers?: { from: string; to: string; usdc: number; block: number }[]; agents?: Record<string, { owner: string; wallet?: string; uri: string }>; failLogs?: boolean; hosts?: string[] } = {}): Route {
  const head = o.head ?? 40_000_000;
  const hosts = o.hosts ?? ["base-rpc.publicnode.com"];
  return async (url, init) => {
    if (!hosts.includes(new URL(url).hostname) || init?.method !== "POST") return undefined;
    const body = JSON.parse(String(init.body));
    const arr = Array.isArray(body) ? body : [body];
    const out = arr.map((c: any) => {
      if (c.method === "eth_blockNumber") return { jsonrpc: "2.0", id: c.id, result: "0x" + head.toString(16) };
      if (c.method === "eth_getLogs") {
        if (o.failLogs) return { jsonrpc: "2.0", id: c.id, error: { code: -32000, message: "exceed max block range" } };
        const q = c.params[0], from = parseInt(q.fromBlock, 16), to = parseInt(q.toBlock, 16);
        const logs = (o.transfers ?? []).filter((t) => t.block >= from && t.block <= to && (!q.topics[1] || topicAddr(t.from) === q.topics[1]) && (!q.topics[2] || topicAddr(t.to) === q.topics[2]))
          .map((t) => ({ address: USDC.toLowerCase(), topics: [T, topicAddr(t.from), topicAddr(t.to)], data: "0x" + word(BigInt(Math.round(t.usdc * 1e6)).toString(16)), blockNumber: "0x" + t.block.toString(16) }));
        return { jsonrpc: "2.0", id: c.id, result: logs };
      }
      if (c.method === "eth_call") {
        const d: string = c.params[0].data.slice(2); const s = d.slice(0, 8); const id = BigInt("0x" + d.slice(8)).toString();
        const a = o.agents?.[id];
        if (!a) return { jsonrpc: "2.0", id: c.id, error: { code: 3, message: "execution reverted: ERC721NonexistentToken" } };
        if (s === sel("ownerOf(uint256)")) return { jsonrpc: "2.0", id: c.id, result: "0x" + word(a.owner) };
        if (s === sel("tokenURI(uint256)")) return { jsonrpc: "2.0", id: c.id, result: abiString(a.uri) };
        if (s === sel("getAgentWallet(uint256)")) return { jsonrpc: "2.0", id: c.id, result: "0x" + word(a.wallet ?? "0x0") };
      }
      return { jsonrpc: "2.0", id: c.id, error: { code: -32601, message: "unsupported in fake" } };
    });
    return json(Array.isArray(body) ? out : out[0]);
  };
}
export function memKV() {
  const m = new Map<string, { v: string; meta: any }>();
  let failPut = false;
  const kv: any = {
    async put(k: string, v: string, o: any) { if (failPut) throw new Error("KV put() limit exceeded for the day."); m.set(k, { v, meta: o?.metadata }); },
    async get(k: string, t?: string) { const e = m.get(k); return e ? (t === "json" ? JSON.parse(e.v) : e.v) : null; },
    async list(o: any) { const keys = [...m.keys()].filter((k) => k.startsWith(o.prefix ?? "")).sort().map((name) => ({ name, metadata: m.get(name)!.meta })); return { keys, list_complete: true }; },
  };
  return { kv: kv as KVNamespace, m, setFailPut: (b: boolean) => { failPut = b; } };
}
