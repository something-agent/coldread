import { Hono } from "hono";
import { cors } from "hono/cors";
import { BadRequest, Parts, parseInput } from "./check";
import { signedReport } from "./report";
import { verifyEnvelope } from "./envelope";
import { loadReportKey, ReportKey } from "./sign";
import { KEYS } from "./keys";
import { callerHash, getReport, listAll, putReport, stats, uaClass } from "./store";
import { landing, llmsTxt, openapi, serverCard, VERSION } from "./docs";
import { handleMcp, ToolError } from "./mcp";

export interface Env { REPORTS?: KVNamespace; REPORT_KEY?: string; CALLER_SALT?: string; /** self service binding to the Parts entrypoint */ PARTS?: Parts }
const MAX_BODY = 65_536;
const hits = new Map<string, { n: number; t: number }>();
/** Best-effort per-isolate limiter (checks are expensive upstream: ~10 fetches + 3 RPC batches). */
export function limited(ip: string, cost: number, now = Date.now(), cap = 12): boolean {
  const e = hits.get(ip);
  if (!e || now - e.t > 60_000) { hits.set(ip, { n: cost, t: now }); if (hits.size > 5000) hits.clear(); return false; }
  e.n += cost; return e.n > cap;
}

let keyCache: { src: string; key: ReportKey | null } | undefined;
async function reportKey(env: Env) {
  if (!keyCache || keyCache.src !== env.REPORT_KEY) keyCache = { src: env.REPORT_KEY ?? "", key: await loadReportKey(env.REPORT_KEY) };
  return keyCache.key;
}

export function buildApp(opts: { fetchImpl?: typeof fetch; now?: () => Date } = {}) {
  const app = new Hono<{ Bindings: Env }>();
  app.use("*", cors({ origin: "*", allowMethods: ["GET", "POST", "OPTIONS"], allowHeaders: ["content-type", "mcp-protocol-version", "mcp-session-id"] }));
  const origin = (c: any) => new URL(c.req.url).origin;
  const ip = (c: any) => c.req.header("cf-connecting-ip") ?? "local";

  /** The one place a check runs, for HTTP and MCP alike. */
  async function check(c: any, args: any, tool: "http" | "mcp") {
    const input = parseInput(args);
    const now = opts.now?.() ?? new Date();
    const env = await signedReport(input, { fetchImpl: opts.fetchImpl ?? fetch, now, key: await reportKey(c.env ?? {}), keysUrl: `${origin(c)}/.well-known/coldread-keys.json`, runFrom: "cloudflare_worker", parts: c.env?.PARTS, payerCache: async (k) => (c.env?.REPORTS ? await c.env.REPORTS.get(k, "json") : null) as any });
    const report: any = env.report;
    const day = now.toISOString().slice(0, 10);
    const st = await putReport(c.env?.REPORTS, env, { d: day, c: await callerHash(c.env?.CALLER_SALT ?? "unsalted", ip(c), day), u: uaClass(c.req.header("user-agent")), t: tool, v: report.overall, h: report.subject.host });
    return { ...env, stored: st.stored, ...(st.reason ? { stored_note: st.reason } : {}), ...(st.stored ? { report_url: `${origin(c)}/v1/report/${env.digest.hex}` } : {}), anchor: { status: "pending", how: "digests are collected daily and stamped with OpenTimestamps (Bitcoin) in https://github.com/something-agent/buildlog/tree/main/coldread", ...(st.stored ? {} : { note: "not stored, so it will not be in the daily anchor batch" }) } };
  }
  const getStored = async (c: any, hex: string) => { const r = await getReport(c.env?.REPORTS, String(hex ?? "").toLowerCase()); return r; };

  app.get("/", (c) => c.html(landing(origin(c))));
  app.get("/health", (c) => c.json({ ok: true, service: "coldread", version: VERSION }));
  app.get("/llms.txt", (c) => c.text(llmsTxt(origin(c))));
  app.get("/openapi.json", (c) => c.json(openapi(origin(c))));
  app.get("/.well-known/coldread-keys.json", (c) => c.json(KEYS));
  app.get("/.well-known/mcp-server-card.json", (c) => c.json(serverCard(origin(c))));

  const runCheckRoute = async (c: any, args: any) => {
    if (limited(ip(c), 1)) return c.json({ error: "rate_limited", detail: "free tier: up to 12 checks per minute per IP (best effort)" }, 429);
    try { return c.json(await check(c, args, "http")); }
    catch (e) { if (e instanceof BadRequest) return c.json({ error: "bad_request", detail: e.message }, 400); throw e; }
  };
  app.post("/v1/check", async (c) => {
    const raw = await c.req.text();
    if (raw.length > MAX_BODY) return c.json({ error: "too_large" }, 413);
    let a: any; try { a = JSON.parse(raw); } catch { return c.json({ error: "bad_json" }, 400); }
    return runCheckRoute(c, a);
  });
  app.get("/v1/check", (c) => runCheckRoute(c, Object.fromEntries(new URL(c.req.url).searchParams)));
  app.get("/v1/report/:digest", async (c) => { const r = await getStored(c, c.req.param("digest")); return r ? c.json(r) : c.json({ error: "not_found" }, 404); });
  app.post("/v1/verify", async (c) => {
    let a: any; try { a = await c.req.json(); } catch { return c.json({ error: "bad_json" }, 400); }
    return c.json(await verifyEnvelope(a?.envelope ?? a, KEYS.keys));
  });

  const cached = async (c: any, key: string, ttl: number, make: () => Promise<any>) => {
    const cache = (globalThis as any).caches?.default as Cache | undefined;
    const req = new Request(`${origin(c)}/__cache/${key}`);
    if (cache) { const hit = await cache.match(req); if (hit) return new Response(hit.body, hit); }
    const res = new Response(JSON.stringify(await make()), { headers: { "content-type": "application/json", "cache-control": `public, max-age=${ttl}` } });
    if (cache) c.executionCtx?.waitUntil?.(cache.put(req, res.clone()));
    return res;
  };
  app.get("/v1/digests", async (c) => {
    const date = c.req.query("date") ?? "";
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return c.json({ error: "bad_request", detail: "date=YYYY-MM-DD" }, 400);
    if (!c.env?.REPORTS) return c.json({ date, digests: [] });
    return cached(c, `digests-${date}`, 600, async () => { const ks = await listAll(c.env.REPORTS!); return { date, digests: ks.filter((k) => k.metadata?.d === date).map((k) => k.name.slice(2)).sort() }; });
  });
  app.get("/v1/stats", async (c) => {
    if (!c.env?.REPORTS) return c.json(stats([]));
    return cached(c, "stats", 600, async () => ({ ...stats(await listAll(c.env.REPORTS!)), generated_at: new Date().toISOString(), cache_seconds: 600 }));
  });

  app.post("/mcp", async (c) => {
    if (limited(ip(c), 1, Date.now(), 30)) return c.json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "rate limited" } }, 429);
    const raw = await c.req.text();
    if (raw.length > MAX_BODY) return c.json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "body too large" } }, 413);
    let msg: any; try { msg = JSON.parse(raw); } catch { return c.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
    let checks = 0;
    const run = async (name: string, a: any) => {
      if (name === "coldread_check" && ++checks > 1) throw new ToolError("one coldread_check per request (Workers Free subrequest limit); send it separately");
      if (name === "coldread_check") { try { return await check(c, a, "mcp"); } catch (e) { if (e instanceof BadRequest) throw new ToolError(e.message); throw e; } }
      if (name === "coldread_get_report") { const r = await getStored(c, a?.digest); if (!r) throw new ToolError("no stored report with that digest"); return r; }
      return verifyEnvelope(a?.envelope ?? a, KEYS.keys);
    };
    const one = (m: any) => handleMcp(m, run, VERSION);
    if (Array.isArray(msg)) { const outs = (await Promise.all(msg.slice(0, 3).map(one))).filter((x) => x !== null); return outs.length ? c.json(outs) : c.body(null, 202); }
    const out = await one(msg);
    return out === null ? c.body(null, 202) : c.json(out);
  });
  app.get("/mcp", (c) => c.json({ error: "method_not_allowed", detail: "POST JSON-RPC to /mcp (stateless Streamable HTTP)" }, 405));
  app.notFound((c) => c.json({ error: "not_found", docs: `${origin(c)}/llms.txt` }, 404));
  app.onError((e, c) => c.json({ error: "internal", detail: e.message.slice(0, 200) }, 500));
  return app;
}
