/**
 * Outbound fetch guard. Cloudflare Workers fetch from the edge and cannot reach private networks, but we still refuse
 * non-public targets so the tool can't be used to poke at anything odd, and we cap time, size and redirects.
 * Each hop is one Workers subrequest (free plan: 50 per invocation).
 */
export const UA = "coldread/0.1 (+https://github.com/something-agent/coldread; read-only trust check)";
export class BlockedTarget extends Error {}

function v4(ip: string): number[] | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  return p.some((x) => x > 255) ? null : p;
}
function publicV4(p: number[]): boolean {
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || (b === 0 && p[2] <= 2) || (b === 88 && p[2] === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && p[2] === 100))) return false;
  if (a === 203 && b === 0 && p[2] === 113) return false;
  return true;
}

/** Throws BlockedTarget unless the URL is a plain public https (or, if allowHttp, http) URL on a default port. */
export function assertPublicUrl(raw: string, allowHttp = false): URL {
  let u: URL;
  try { u = new URL(raw); } catch { throw new BlockedTarget("not a valid absolute URL"); }
  const scheme = u.protocol.replace(":", "");
  if (scheme !== "https" && !(allowHttp && scheme === "http")) throw new BlockedTarget(`scheme '${scheme}' not allowed (https only${allowHttp ? " or http" : ""})`);
  if (u.username || u.password) throw new BlockedTarget("credentials in URL are not allowed");
  if (u.port && !((scheme === "https" && u.port === "443") || (scheme === "http" && u.port === "80"))) throw new BlockedTarget("non-default ports are not allowed");
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host === "localhost" || /\.(local|internal|localhost|lan|home|corp|onion)$/.test(host)) throw new BlockedTarget("local hostnames are not allowed");
  if (host.startsWith("[") || host.includes(":")) throw new BlockedTarget("IPv6 literals are not allowed");
  const ip = v4(host);
  if (ip) { if (!publicV4(ip)) throw new BlockedTarget("host is a non-public address"); throw new BlockedTarget("IP-literal hosts are not allowed; use a hostname"); }
  if (/^[0-9.x]+$/i.test(host) || /^\d+$/.test(host)) throw new BlockedTarget("numeric host forms are not allowed");
  if (!host.includes(".")) throw new BlockedTarget("single-label hostnames are not allowed");
  return u;
}

export interface Fetched { url: string; status: number; headers: Record<string, string>; body: Uint8Array; truncated: boolean; redirects: string[] }

export async function safeFetch(raw: string, o: { method?: string; body?: string; headers?: Record<string, string>; maxBytes?: number; timeoutMs?: number; maxRedirects?: number; allowHttp?: boolean; fetchImpl?: typeof fetch } = {}): Promise<Fetched> {
  const f = o.fetchImpl ?? fetch;
  const max = o.maxBytes ?? 262_144;
  let url = assertPublicUrl(raw, o.allowHttp).href;
  const redirects: string[] = [];
  for (let hop = 0; hop <= (o.maxRedirects ?? 3); hop++) {
    const r = await f(url, {
      method: o.method ?? "GET", body: o.body, redirect: "manual", signal: AbortSignal.timeout(o.timeoutMs ?? 8000),
      headers: { "user-agent": UA, accept: "application/json, text/plain;q=0.8, */*;q=0.5", ...(o.headers ?? {}) },
    });
    if ([301, 302, 303, 307, 308].includes(r.status)) {
      const loc = r.headers.get("location");
      try { await r.body?.cancel(); } catch { /* ignore */ }
      if (!loc) throw new Error("redirect without location");
      url = assertPublicUrl(new URL(loc, url).href, o.allowHttp).href;
      redirects.push(url);
      continue;
    }
    const reader = r.body?.getReader();
    const chunks: Uint8Array[] = [];
    let n = 0, truncated = false;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        n += value.length;
        if (n > max) { truncated = true; try { await reader.cancel(); } catch { /* ignore */ } chunks.push(value.slice(0, value.length - (n - max))); break; }
        chunks.push(value);
      }
    }
    const body = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
    let off = 0; for (const c of chunks) { body.set(c, off); off += c.length; }
    const headers: Record<string, string> = {};
    r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { url, status: r.status, headers, body, truncated, redirects };
  }
  throw new Error("too many redirects");
}
