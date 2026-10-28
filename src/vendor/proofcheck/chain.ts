/** Minimal read-only ERC-8004 + JSON-RPC access. No keys, no indexer: public RPC endpoints only (eth_call). */
import { keccak_256 } from "@noble/hashes/sha3";
import { b64Decode, bytesToHex, dec, enc, hexToBytes } from "./bytes";
import { safeFetch, UA } from "./safe";

/** ERC-8004 Identity Registry singleton; same address on each chain below (eth_getCode verified 2026-10-27). */
export const IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";

export const CHAIN_RPCS: Record<number, string[]> = {
  1: ["https://ethereum-rpc.publicnode.com"],
  8453: ["https://base-rpc.publicnode.com", "https://base.drpc.org", "https://mainnet.base.org"],
  10: ["https://optimism-rpc.publicnode.com", "https://optimism.drpc.org", "https://mainnet.optimism.io"],
  42161: ["https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.drpc.org", "https://arb1.arbitrum.io/rpc"],
  137: ["https://polygon-bor-rpc.publicnode.com"],
  56: ["https://bsc-rpc.publicnode.com"],
  43114: ["https://avalanche-c-chain-rpc.publicnode.com", "https://api.avax.network/ext/bc/C/rpc"],
  100: ["https://gnosis-rpc.publicnode.com", "https://rpc.gnosischain.com"],
  42220: ["https://celo-rpc.publicnode.com", "https://forno.celo.org"],
  59144: ["https://linea-rpc.publicnode.com", "https://rpc.linea.build"],
  534352: ["https://scroll-rpc.publicnode.com", "https://rpc.scroll.io"],
};

const sel = (sig: string) => bytesToHex(keccak_256(enc.encode(sig)).slice(0, 4));
const SEL = { ownerOf: sel("ownerOf(uint256)"), tokenURI: sel("tokenURI(uint256)"), getAgentWallet: sel("getAgentWallet(uint256)") };
const word = (n: bigint) => n.toString(16).padStart(64, "0");

export interface RpcResult { ok: boolean; result?: string; error?: string }

/** One JSON-RPC batch = one subrequest. Per-item errors (e.g. reverts) are returned, not thrown. */
export async function rpcBatch(urls: string[], calls: { to: string; data: string }[], fetchImpl?: typeof fetch): Promise<RpcResult[]> {
  const body = JSON.stringify(calls.map((c, i) => ({ jsonrpc: "2.0", id: i + 1, method: "eth_call", params: [{ to: c.to, data: "0x" + c.data }, "latest"] })));
  let lastErr = "no rpc";
  for (const u of urls) {
    try {
      const r = await (fetchImpl ?? fetch)(u, { method: "POST", headers: { "content-type": "application/json", "user-agent": UA }, body, signal: AbortSignal.timeout(8000) });
      if (!r.ok) { lastErr = `rpc http ${r.status}`; continue; }
      const j = await r.json() as any;
      const arr: any[] = Array.isArray(j) ? j : [j];
      const out: RpcResult[] = calls.map(() => ({ ok: false, error: "missing response" }));
      for (const it of arr) {
        const idx = Number(it?.id) - 1;
        if (!(idx >= 0 && idx < calls.length)) continue;
        out[idx] = typeof it.result === "string" ? { ok: true, result: it.result } : { ok: false, error: String(it?.error?.message ?? "error").slice(0, 120) };
      }
      // A provider that rejects batches answers every item with an error: try next endpoint.
      if (out.every((x) => !x.ok && /batch|too many|not supported/i.test(x.error ?? ""))) { lastErr = out[0].error ?? "batch rejected"; continue; }
      return out;
    } catch (e) { lastErr = (e as Error).message; }
  }
  return calls.map(() => ({ ok: false, error: lastErr }));
}

function decodeAddress(hex: string): string | null {
  const h = hex.replace(/^0x/, "");
  if (h.length < 64) return null;
  const a = h.slice(24, 64);
  return /^0+$/.test(a) ? null : "0x" + a;
}
function decodeString(hex: string): string | null {
  try {
    const b = hexToBytes(hex);
    if (b.length < 64) return null;
    const off = Number(BigInt("0x" + bytesToHex(b.slice(0, 32))));
    const len = Number(BigInt("0x" + bytesToHex(b.slice(off, off + 32))));
    if (len > 100_000 || off + 32 + len > b.length) return null;
    return dec.decode(b.slice(off + 32, off + 32 + len));
  } catch { return null; }
}

export interface AgentOnchain { chainId: number; registry: string; agentId: string; owner: string | null; agentWallet: string | null; agentURI: string | null; errors: string[] }

export async function readAgent(chainId: number, agentId: string, opts: { registry?: string; rpcUrls?: string[]; fetchImpl?: typeof fetch } = {}): Promise<AgentOnchain> {
  const registry = opts.registry ?? IDENTITY_REGISTRY;
  const urls = opts.rpcUrls ?? CHAIN_RPCS[chainId];
  if (!urls) throw new Error(`unsupported chain ${chainId}; supported: ${Object.keys(CHAIN_RPCS).join(", ")}`);
  if (!/^\d{1,30}$/.test(agentId)) throw new Error("agentId must be a decimal integer");
  const arg = word(BigInt(agentId));
  const [o, u, w] = await rpcBatch(urls, [SEL.ownerOf, SEL.tokenURI, SEL.getAgentWallet].map((s) => ({ to: registry, data: s + arg })), opts.fetchImpl);
  const errors: string[] = [];
  if (!o.ok) errors.push(`ownerOf: ${o.error}`);
  if (!u.ok) errors.push(`tokenURI: ${u.error}`);
  if (!w.ok) errors.push(`getAgentWallet: ${w.error}`);
  return {
    chainId, registry, agentId,
    owner: o.ok ? decodeAddress(o.result!) : null,
    agentWallet: w.ok ? decodeAddress(w.result!) : null,
    agentURI: u.ok ? decodeString(u.result!) : null,
    errors,
  };
}

/** Load the registration file behind an agentURI (data:, https:, ipfs://). Returns parsed JSON. */
export async function loadRegistration(uri: string, fetchImpl?: typeof fetch): Promise<any> {
  if (uri.startsWith("data:")) {
    const m = uri.match(/^data:([^,;]*)((?:;[^,;]*)*),(.*)$/s);
    if (!m) throw new Error("malformed data: URI");
    const isB64 = /;base64/i.test(m[2]);
    const text = isB64 ? dec.decode(b64Decode(m[3])) : decodeURIComponent(m[3]);
    if (text.length > 262_144) throw new Error("registration file too large");
    return JSON.parse(text);
  }
  let url = uri;
  if (uri.startsWith("ipfs://")) url = "https://ipfs.io/ipfs/" + uri.slice(7);
  const r = await safeFetch(url, { fetchImpl, maxBytes: 262_144 });
  if (r.status !== 200) throw new Error(`registration file HTTP ${r.status}`);
  return JSON.parse(dec.decode(r.body));
}
