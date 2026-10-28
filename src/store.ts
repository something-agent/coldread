/** Report storage and privacy-preserving usage counters in Workers KV (free tier: 1000 writes/day, 1000 lists/day).
 *  One KV write per stored report; counters live in the key's metadata, so counting costs no extra write.
 *  Callers are recorded only as a salted, day-scoped hash (not reversible to an IP without the secret salt). */
import { sha256Hex } from "./canon";

export interface Meta { d: string; c: string; u: string; t: "http" | "mcp"; v: string; h: string }
export const TTL = 90 * 86400;

export function uaClass(ua: string | undefined): string {
  const s = (ua ?? "").toLowerCase();
  if (!s) return "none";
  if (s.includes("coldread-selftest")) return "self";
  if (/bot|crawl|spider|scan|monitor|uptime|preview/.test(s) && !/mcp|agent/.test(s)) return "crawler";
  if (/mcp|claude|cursor|openai|anthropic|langchain|agent/.test(s)) return "agent";
  if (/curl|python|node|undici|axios|go-http|httpx|requests|wget|deno|bun/.test(s)) return "script";
  if (/mozilla/.test(s)) return "browser";
  return "other";
}

export const callerHash = async (salt: string, ip: string, day: string) => (await sha256Hex(`${salt}|${day}|${ip}`)).slice(0, 16);

export async function putReport(kv: KVNamespace | undefined, envelope: any, meta: Meta): Promise<{ stored: boolean; reason?: string }> {
  if (!kv) return { stored: false, reason: "no storage bound" };
  try { await kv.put(`r:${envelope.digest.hex}`, JSON.stringify(envelope), { expirationTtl: TTL, metadata: meta }); return { stored: true }; }
  catch (e) { return { stored: false, reason: `storage unavailable (likely the free daily write cap): ${(e as Error).message.slice(0, 100)}` }; }
}

export async function getReport(kv: KVNamespace | undefined, hex: string) {
  if (!kv || !/^[0-9a-f]{64}$/.test(hex)) return null;
  return kv.get(`r:${hex}`, "json");
}

/** All stored keys with metadata (bounded). Used by /v1/digests and /v1/stats, both cached. */
export async function listAll(kv: KVNamespace, max = 5000) {
  const out: { name: string; metadata: Meta }[] = [];
  let cursor: string | undefined;
  do {
    const r: any = await kv.list({ prefix: "r:", cursor, limit: 1000 });
    for (const k of r.keys) out.push({ name: k.name, metadata: k.metadata as Meta });
    cursor = r.list_complete ? undefined : r.cursor;
  } while (cursor && out.length < max);
  return out;
}

export function stats(keys: { metadata: Meta }[]) {
  const days: Record<string, any> = {};
  const all = { checks: 0, outside_checks: 0, distinct_outside_callers_by_day: 0 } as any;
  for (const { metadata: m } of keys) {
    if (!m) continue;
    const d = (days[m.d] ??= { checks: 0, by_ua: {}, by_tool: {}, by_overall: {}, outside_checks: 0, _c: new Set<string>(), outside_hosts: new Set<string>() });
    d.checks++; all.checks++;
    d.by_ua[m.u] = (d.by_ua[m.u] ?? 0) + 1;
    d.by_tool[m.t] = (d.by_tool[m.t] ?? 0) + 1;
    d.by_overall[m.v] = (d.by_overall[m.v] ?? 0) + 1;
    if (m.u !== "self" && m.u !== "crawler") { d.outside_checks++; all.outside_checks++; d._c.add(m.c); d.outside_hosts.add(m.h); }
  }
  for (const d of Object.values(days)) { d.distinct_outside_callers = d._c.size; all.distinct_outside_callers_by_day += d._c.size; d.distinct_hosts_checked_by_outside = d.outside_hosts.size; delete d._c; delete d.outside_hosts; }
  return { totals: all, days, notes: ["outside = not our self-tests (user agent coldread-selftest) and not crawler-like user agents", "callers are salted day-scoped hashes; the same caller on two days counts twice", "reports expire after 90 days, so totals cover at most that window", "a check whose report could not be stored (free-tier write cap) is not counted"] };
}
