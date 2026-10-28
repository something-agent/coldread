/** x402 unpaid-path linter. Everything here is read-only: we never pay, sign or hold a key. */
import { keccak_256 } from "@noble/hashes/sha3";
import { b64Decode, base58Decode, dec, enc } from "./bytes";
import { CAIP2, KNOWN_ASSETS, TESTNETS, V1_NETWORKS } from "./known";
import { assertPublicUrl, Fetched, safeFetch } from "./safe";
import { directoryReadiness, DirResult } from "./directories";

export type Severity = "error" | "warn" | "info";
export interface Finding { id: string; severity: Severity; message: string; fix?: string; where?: string }
export interface Ctx { fetchImpl?: typeof fetch; allowPrivate?: boolean }

const F = (id: string, severity: Severity, message: string, fix?: string, where?: string): Finding => ({ id, severity, message, ...(fix ? { fix } : {}), ...(where ? { where } : {}) });
const bytesToHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export function eip55(addr: string): string {
  const a = addr.slice(2).toLowerCase();
  const h = bytesToHex(keccak_256(enc.encode(a)));
  let out = "0x";
  for (let i = 0; i < a.length; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}

export function parsePaymentRequired(headers: Record<string, string>, body: Uint8Array): { pr: any | null; from: "header" | "body" | null; error?: string } {
  const h = headers["payment-required"];
  let headerErr: string | undefined;
  if (h) { try { return { pr: JSON.parse(dec.decode(b64Decode(h))), from: "header" }; } catch { headerErr = "PAYMENT-REQUIRED header is present but is not base64-encoded JSON"; } }
  try {
    const j = JSON.parse(dec.decode(body));
    if (j && typeof j === "object" && Array.isArray(j.accepts)) return { pr: j, from: "body", error: headerErr };
    return { pr: null, from: null, error: headerErr ?? "402 body is JSON but has no accepts[]" };
  } catch { return { pr: null, from: null, error: headerErr ?? "no PAYMENT-REQUIRED header and the 402 body is not JSON" }; }
}

/** Pure lint of a decoded PaymentRequired object. `url` is the URL that was requested (for resource checks). */
export function lintPaymentRequired(pr: any, o: { url?: string; from?: "header" | "body" | null } = {}): { findings: Finding[]; summary: any } {
  const f: Finding[] = [];
  const ver = pr?.x402Version;
  if (ver === 2) { /* ok */ }
  else if (ver === 1) f.push(F("X102", "warn", "x402Version is 1 (legacy). v2 clients expect the PAYMENT-REQUIRED header and CAIP-2 network ids.", "Serve x402Version 2 (keep v1 behind a separate path if you still need it)."));
  else f.push(F("X102", "error", `x402Version is ${JSON.stringify(ver)}; expected 2 (or 1 for legacy).`, "Set x402Version: 2."));
  if (o.from === "body" && ver === 2) f.push(F("X103", "warn", "The v2 challenge was found in the response body only, with no PAYMENT-REQUIRED header. Some v2 clients read only the header.", "Also send the base64-encoded PaymentRequired JSON in a PAYMENT-REQUIRED response header."));

  const accepts: any[] = Array.isArray(pr?.accepts) ? pr.accepts : [];
  if (!accepts.length) f.push(F("X110", "error", "accepts[] is missing or empty: a client has nothing to pay.", "List at least one payment option in accepts[]."));
  const amountKey = ver === 1 ? "maxAmountRequired" : "amount";
  const prices: string[] = [];
  const payTos = new Set<string>();
  accepts.forEach((a, i) => {
    const w = `accepts[${i}]`;
    const need = ["scheme", "network", "asset", "payTo", amountKey];
    const missing = need.filter((k) => a?.[k] === undefined || a?.[k] === null || a?.[k] === "");
    if (missing.length) f.push(F("X110", "error", `Missing required field(s): ${missing.join(", ")}.`, ver === 1 ? "v1 uses maxAmountRequired." : "v2 uses amount (not maxAmountRequired).", w));
    if (ver === 2 && a?.maxAmountRequired !== undefined && a?.amount === undefined) f.push(F("X110", "error", "Uses v1 field maxAmountRequired in a v2 challenge; v2 clients read amount.", "Rename to amount.", w));
    const net: string = String(a?.network ?? "");
    if (net) {
      if (ver === 2 && !CAIP2.test(net)) f.push(F("X111", "error", `network '${net}' is not a CAIP-2 id (e.g. eip155:8453).`, "Use CAIP-2 ids in v2.", w));
      else if (ver === 1 && !CAIP2.test(net) && !V1_NETWORKS.has(net)) f.push(F("X111", "warn", `network '${net}' is not a known v1 network name.`, undefined, w));
      if (TESTNETS.has(net)) f.push(F("X112", "warn", `network '${net}' is a testnet. Fine for staging; real agents will not pay it.`, "Offer a mainnet option before announcing.", w));
    }
    const scheme = String(a?.scheme ?? "");
    if (scheme && !["exact", "upto"].includes(scheme)) f.push(F("X117", "warn", `scheme '${scheme}' is not 'exact' or 'upto'; most clients and facilitators will not support it.`, undefined, w));
    const payTo = String(a?.payTo ?? "");
    const isEvm = net.startsWith("eip155:") || (ver === 1 && !net.startsWith("solana") && net !== "solana");
    const isSol = net.startsWith("solana");
    if (payTo) {
      payTos.add(payTo.toLowerCase());
      if (isEvm) {
        if (!/^0x[0-9a-fA-F]{40}$/.test(payTo)) f.push(F("X113", "error", `payTo '${payTo}' is not a 20-byte 0x address.`, undefined, w));
        else {
          if (/^0x0{40}$/i.test(payTo) || /^0x0{39}1$/i.test(payTo) || /^0x0{36}dead$/i.test(payTo) || /^0xdead0{32}dead$/i.test(payTo)) f.push(F("X113", "error", "payTo is the zero/burn address: payments would be lost.", undefined, w));
          const body = payTo.slice(2);
          if (body !== body.toLowerCase() && body !== body.toUpperCase() && eip55(payTo) !== payTo) f.push(F("X113", "error", `payTo has mixed case but fails the EIP-55 checksum (expected ${eip55(payTo)}). Likely a typo.`, "Use the checksummed address.", w));
          if (String(a?.asset ?? "").toLowerCase() === payTo.toLowerCase()) f.push(F("X114", "error", "payTo equals the asset contract address: funds would be sent to the token contract.", undefined, w));
        }
      } else if (isSol) {
        try { if (base58Decode(payTo).length !== 32) throw new Error(); } catch { f.push(F("X113", "error", `payTo '${payTo.slice(0, 12)}…' is not a valid Solana address (base58, 32 bytes).`, undefined, w)); }
      }
    }
    const amt = a?.[amountKey];
    const asset = String(a?.asset ?? "");
    const known = KNOWN_ASSETS.get(asset.toLowerCase());
    if (amt !== undefined && amt !== null && amt !== "") {
      if (!/^\d+$/.test(String(amt))) f.push(F("X115", "error", `${amountKey} '${amt}' must be a non-negative integer string in the asset's smallest unit.`, "Use e.g. \"10000\" for 0.01 USDC.", w));
      else if (BigInt(String(amt)) === 0n) f.push(F("X115", "warn", `${amountKey} is 0: this is a free route; no payment is needed.`, "Drop the 402 for free routes.", w));
      else if (known) {
        const usd = Number(BigInt(String(amt))) / 10 ** known.decimals;
        prices.push(`${usd} ${known.symbol}`);
        if (usd >= 5) f.push(F("X115", "info", `Price is ${usd} ${known.symbol} per call. Agents with per-call caps may refuse; consider a lower per-call price.`, undefined, w));
        if (usd < 0.0001) f.push(F("X115", "warn", `Price is ${usd} ${known.symbol}: below the point where gas/facilitator costs usually matter.`, undefined, w));
      }
    }
    if (asset) {
      if (known && known.network !== net && ver === 2) f.push(F("X116", "warn", `asset ${asset} is ${known.symbol} on ${known.network}, but network is ${net}.`, "Check the network/asset pair.", w));
      else if (!known) f.push(F("X116", "info", `asset ${asset.length > 20 ? asset.slice(0, 10) + "…" : asset} is not a USDC deployment I recognise; clients must trust and support it.`, undefined, w));
    }
    if (isEvm && scheme === "exact") {
      const ex = a?.extra ?? {};
      if (!ex?.name || !ex?.version) f.push(F("X118", "error", "EVM 'exact' needs extra.name and extra.version (the token's EIP-712 domain). Without them, EIP-3009 clients cannot build the typed data to sign.", `Add "extra": {"name":"${known?.eip712?.name ?? "<token name>"}","version":"${known?.eip712?.version ?? "<token version>"}"}.`, w));
      else if (known?.eip712 && (String(ex.name) !== known.eip712.name || String(ex.version) !== known.eip712.version)) f.push(F("X118", "warn", `extra.name/version is "${ex.name}"/"${ex.version}" but this USDC's EIP-712 domain is "${known.eip712.name}"/"${known.eip712.version}". A wrong domain makes every signature fail on-chain.`, undefined, w));
    }
    const t = a?.maxTimeoutSeconds;
    if (t === undefined) f.push(F("X119", "warn", "maxTimeoutSeconds is missing.", "Set it (e.g. 60).", w));
    else if (typeof t !== "number" || !(t > 0) || t > 3600) f.push(F("X119", "warn", `maxTimeoutSeconds ${JSON.stringify(t)} looks wrong (expected 1..3600).`, undefined, w));
    else if (t < 10) f.push(F("X119", "warn", `maxTimeoutSeconds is ${t}: very short for a facilitator round trip.`, undefined, w));
  });
  if (payTos.size > 1) f.push(F("X120", "info", `accepts[] uses ${payTos.size} different payTo addresses; make sure that is intentional.`));

  if (ver === 2) {
    const res = pr?.resource;
    if (!res || typeof res !== "object") f.push(F("X130", "warn", "No resource object in the v2 challenge; clients and signed offers have nothing to bind to.", "Add resource: {url, description, mimeType}."));
    else {
      if (!res.url) f.push(F("X130", "warn", "resource.url is missing.", undefined, "resource"));
      else if (o.url) {
        try { const a = new URL(res.url), b = new URL(o.url); if (a.host !== b.host) f.push(F("X130", "warn", `resource.url host (${a.host}) differs from the requested host (${b.host}).`, undefined, "resource")); } catch { f.push(F("X130", "warn", "resource.url is not a valid URL.", undefined, "resource")); }
      }
      if (!res.description) f.push(F("X130", "info", "resource.description is empty: discovery catalogs show it to agents choosing what to call.", undefined, "resource"));
    }
  }
  const ext = Object.keys(pr?.extensions ?? {});
  if (!ext.includes("bazaar")) f.push(F("X131", "info", "No bazaar extension: Bazaar-style discovery catalogs may not list this endpoint (input/output schema lives there).", "Declare extensions.bazaar with an input example and output schema if you want discovery."));
  return { findings: f, summary: { x402_version: ver ?? null, accepts: accepts.length, prices, extensions: ext } };
}

const sevRank: Record<Severity, number> = { error: 0, warn: 1, info: 2 };
export function verdictOf(f: Finding[]): "fail" | "warn" | "ok" { return f.some((x) => x.severity === "error") ? "fail" : f.some((x) => x.severity === "warn") ? "warn" : "ok"; }
export const NOT_TESTED = ["settlement (we never pay)", "facilitator verify/settle behaviour", "that the paid response is delivered", "uptime or latency under load"];
/** What a clean lint must never be read as. */
export const SCOPE = "unpaid_path_only";
export const VERDICT_MEANING = "ok means the unpaid 402 challenge and discovery look well-formed to a client or directory. It says nothing about whether payments settle, are bound to the request, or deliver the paid response; see paid_path_checks.";
/** Seller-side failures only a paid call can show. Named so that a clean unpaid lint can never be mistaken for "revenue works". */
export const PAID_PATH_CHECKS = [
  { id: "P001", name: "paid-replay", risk: "The same payment header (X-PAYMENT / PAYMENT-SIGNATURE) is accepted for more than one request: one payment, many paid responses.", how_to_test: "Pay once, then send the identical payment header a second time (ideally with a different body). A second paid 200 is a revenue leak. Key settled payments on (tx_hash, log_index) or the EIP-3009 nonce." },
  { id: "P002", name: "settle-not-called", risk: "The server asks the facilitator to verify but never calls settle: the paid 200 is served and no funds move.", how_to_test: "After one paid call, look for the USDC Transfer to your payTo on-chain (or check the PAYMENT-RESPONSE tx hash). No transfer means verify-only." },
  { id: "P003", name: "paid-200-cacheable", risk: "A paid 200 is heuristically cacheable (RFC 9111) unless it says otherwise, so a CDN or shared proxy can hand the paid body to the next unpaid caller.", how_to_test: "Check the paid response for cache-control: private, no-store; then repeat the same request without payment and confirm you get a 402, not the cached body." },
  { id: "P004", name: "paid-response-delivered", risk: "Settlement succeeds but the handler fails or times out, so the buyer pays and gets an error.", how_to_test: "Make one paid call per route and check the body against your docs; return an explicit not-charged error before settling when the work cannot be done." },
];

/** Parse openapi.json (if fetched whole) and return it, or null. */
function openapiDoc(x?: { r?: Fetched }): any | null {
  if (!x?.r || x.r.status !== 200 || x.r.truncated) return null;
  try { const j = JSON.parse(dec.decode(x.r.body)); return j && typeof j === "object" ? j : null; } catch { return null; }
}
/** Operations (lower-case methods) documented for a path; tolerates a server base path prefix. */
function openapiOps(doc: any, pathname: string): Set<string> | null {
  const paths = doc?.paths; if (!paths || typeof paths !== "object") return null;
  const key = Object.keys(paths).find((k) => k === pathname || (k.length > 1 && pathname.endsWith(k)));
  if (!key) return null;
  return new Set(Object.keys(paths[key] ?? {}).map((m) => m.toLowerCase()).filter((m) => ["get", "post", "put", "patch", "delete"].includes(m)));
}
/** Non-x402 ways in that the operator documents (API key, bearer, prepaid credits). A caller holding them may get 2xx with no 402. */
function altAuth(doc: any, wkText: string | null): string[] {
  const out: string[] = [];
  const ss = doc?.components?.securitySchemes ?? doc?.securityDefinitions;
  if (ss && typeof ss === "object") for (const [name, v] of Object.entries<any>(ss)) if (!/x402/i.test(`${name} ${v?.scheme ?? ""}`)) out.push(`${name} (${v?.type ?? "?"}${v?.in && v?.name ? `: ${v.in} ${v.name}` : v?.scheme ? `: ${v.scheme}` : ""})`);
  if (wkText) { try { const w = JSON.parse(wkText); for (const k of Object.keys(w ?? {})) if (/^(alt_?auth|auth(entication)?|api_?keys?|credits|prepaid|alternate_?(auth|payment)s?)$/i.test(k)) out.push(`/.well-known/x402 "${k}"`); } catch { /* not JSON */ } }
  return [...new Set(out)].slice(0, 6);
}

async function tryFetch(url: string, o: Parameters<typeof safeFetch>[1]): Promise<{ r?: Fetched; ms: number; err?: string }> {
  const t = Date.now();
  try { return { r: await safeFetch(url, o), ms: Date.now() - t }; } catch (e) { return { ms: Date.now() - t, err: (e as Error).message.slice(0, 160) }; }
}

export async function lintEndpoint(rawUrl: string, o: { method?: "auto" | "GET" | "POST"; directories?: boolean }, ctx: Ctx = {}) {
  const u = assertPublicUrl(rawUrl, true, ctx.allowPrivate);
  const method = o.method ?? "auto";
  const f: Finding[] = [];
  const base = { fetchImpl: ctx.fetchImpl, allowHttp: true, maxBytes: 262_144, allowPrivate: ctx.allowPrivate };
  const post = { ...base, method: "POST", body: "{}", headers: { "content-type": "application/json" } };
  const origin = u.origin;
  const [g, p, wk, llms, oapi, pre] = await Promise.all([
    method === "POST" ? Promise.resolve(undefined) : tryFetch(u.href, { ...base, method: "GET" }),
    method === "GET" ? Promise.resolve(undefined) : tryFetch(u.href, post),
    tryFetch(origin + "/.well-known/x402", { ...base, maxBytes: 65_536, maxRedirects: 1 }),
    tryFetch(origin + "/llms.txt", { ...base, maxBytes: 4096, maxRedirects: 1 }),
    tryFetch(origin + "/openapi.json", { ...base, maxBytes: 524_288, maxRedirects: 1 }),
    tryFetch(u.href, { ...base, method: "OPTIONS", headers: { origin: "https://agent.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type,payment-signature,x-payment" } }),
  ]);
  const probes: Record<string, any> = {};
  const desc = (x?: { r?: Fetched; ms: number; err?: string }) => x ? (x.r ? { status: x.r.status, ms: x.ms, redirects: x.r.redirects.length } : { error: x.err, ms: x.ms }) : undefined;
  if (g) probes.get = desc(g);
  if (p) probes.post = desc(p);
  const tries = [["GET", g], ["POST", p]] as const;
  const reachable = tries.filter(([, x]) => x?.r);
  if (!reachable.length) {
    f.push(F("X001", "error", `Could not fetch the endpoint: ${(g?.err ?? p?.err) ?? "no response"}.`, "Check DNS/TLS and that the Worker/server answers unauthenticated requests."));
    return { url: u.href, verdict: "fail" as const, summary: null as any, probes, findings: f, not_tested: NOT_TESTED, scope: SCOPE, verdict_meaning: VERDICT_MEANING, paid_path_checks: PAID_PATH_CHECKS };
  }
  const c402 = reachable.filter(([, x]) => x!.r!.status === 402);
  if (!c402.length) {
    f.push(F("X002", "error", `Unpaid ${reachable.map(([m, x]) => `${m} -> ${x!.r!.status}`).join(", ")}: no HTTP 402 challenge.`, "An unpaid request to a paid route must return 402 with the payment requirements."));
  } else if (c402.length === 1 && method === "auto") {
    const other = reachable.find(([m]) => m !== c402[0][0]);
    if (other) f.push(F("X002", "warn", `Only ${c402[0][0]} returns a 402; ${other[0]} returns ${other[1]!.r!.status}. Some directories and probes use ${other[0]}, and will report the route as not an x402 endpoint.`, `Also serve the 402 challenge for ${other[0]} (never settle or serve paid content on it).`));
  }
  // When both methods return a 402, lint the one the challenge itself declares (bazaar info.input.method),
  // so a POST route that also answers GET with a lighter 402 is judged on its real challenge.
  const declaredOf = (x?: { r?: Fetched }) => { try { return String(parsePaymentRequired(x!.r!.headers, x!.r!.body).pr?.extensions?.bazaar?.info?.input?.method ?? "").toUpperCase(); } catch { return ""; } };
  if (c402.length === 2 && c402[0][0] === "GET" && declaredOf(c402[1][1]) === "POST" && declaredOf(c402[0][1]) !== "GET") c402.reverse();
  const [pm, pick] = c402[0] ?? reachable[0];
  const r = pick!.r!;
  if (r.redirects.length) f.push(F("X004", "warn", `The unpaid request was redirected ${r.redirects.length} time(s) (${r.redirects[0]}). Clients often drop the payment header or turn POST into GET on redirect.`, "Serve the 402 at the canonical URL."));
  if (r.url.startsWith("http://") || u.protocol === "http:") f.push(F("X005", "warn", "Endpoint is plain http: payment terms can be tampered with in transit.", "Serve x402 over https only."));
  if (pick!.ms > 5000) f.push(F("X008", "warn", `Slow challenge: ${pick!.ms} ms.`, "A 402 should be near-instant; do the heavy work only after payment."));
  let summary: any = null;
  if (r.status === 402) {
    const ct = (r.headers["content-type"] ?? "").toLowerCase();
    const cc = (r.headers["cache-control"] ?? "").toLowerCase();
    if (/\b(public|max-age=[1-9])/.test(cc) || /s-maxage=[1-9]/.test(cc)) f.push(F("X007", "warn", `402 challenge is cacheable: stale challenge risk (cache-control: ${cc}). A cached 402 whose payTo or amount predates a key or price rotation still looks valid to a client that cannot tell.`, "Send cache-control: no-store on 402s; if an edge must cache, add Vary on the payment header and purge on rotation."));
    const parsed = parsePaymentRequired(r.headers, r.body);
    if (!parsed.pr) f.push(F("X101", "error", parsed.error ?? "Could not parse a PaymentRequired object.", "Return JSON with x402Version and accepts[], and/or the base64 PAYMENT-REQUIRED header."));
    else {
      if (parsed.error) f.push(F("X101", "warn", parsed.error + "; used the body instead."));
      if (parsed.from === "body" && !ct.includes("json")) f.push(F("X006", "warn", `402 body is JSON but content-type is '${ct || "missing"}'.`, "Send content-type: application/json."));
      const lr = lintPaymentRequired(parsed.pr, { url: u.href, from: parsed.from });
      f.push(...lr.findings);
      summary = { ...lr.summary, method: pm, challenge_in: parsed.from };
      // A route that declares its method in the bazaar extension and answers the other one with 404/405 is
      // doing what it says; only crawlers that ignore the declaration miss it. Downgrade X002 to info then.
      const declared = String(parsed.pr?.extensions?.bazaar?.info?.input?.method ?? "").toUpperCase();
      const x2 = f.findIndex((x) => x.id === "X002" && x.severity === "warn");
      const otherSt = tries.find(([m]) => m !== pm)?.[1]?.r?.status;
      if (x2 >= 0 && declared === pm && (otherSt === 404 || otherSt === 405)) {
        f[x2] = F("X002", "info", `Only ${pm} returns a 402 (${pm === "GET" ? "POST" : "GET"} -> ${otherSt}), and the bazaar extension declares method ${pm}, so this is consistent. Probes that ignore the declaration will still miss it.`, otherSt === 404 ? `Optional: answer the other method with 405 and an Allow: ${pm} header, so a probe learns the right method instead of 'not found'.` : undefined);
      }
      // POST-paid route whose GET on the same path is a different REST resource (a collection index next to a
      // create-item POST): GET 200 JSON is not a leak if the method or the API docs say so (spawnxchange_scout's route).
      const getR = tries.find(([m]) => m === "GET")?.[1]?.r;
      if (x2 >= 0 && f[x2].severity === "warn" && pm === "POST" && getR?.status === 200 && /json/i.test(getR.headers["content-type"] ?? "")) {
        const ops = openapiOps(openapiDoc(oapi), u.pathname);
        const why = declared === "POST" ? "the bazaar extension declares method POST" : ops?.has("get") && ops?.has("post") ? "openapi.json documents GET and POST as separate operations on this path" : null;
        if (why) f[x2] = F("X002", "info", `Only POST returns a 402; GET -> 200 JSON, and ${why}, so GET looks like a different REST resource on the same path (e.g. an index), not a free copy of the paid result. GET-only directory probes will still not see a 402.`, "Make sure the GET 200 never returns the paid result.");
        else f[x2] = F("X002", "warn", `${f[x2].message} If GET 200 is a different resource on the same path (a REST index), declare method POST in the bazaar extension or document both operations in openapi.json and this drops to info.`, f[x2].fix);
      }
      // payTo consistency between GET and POST challenges
      const other = tries.find(([m, x]) => m !== pm && x?.r?.status === 402);
      if (other) {
        const o2 = parsePaymentRequired(other[1]!.r!.headers, other[1]!.r!.body).pr;
        const key = (x: any) => JSON.stringify((x?.accepts ?? []).map((a: any) => [a.network, String(a.payTo).toLowerCase(), a.amount ?? a.maxAmountRequired, String(a.asset).toLowerCase()]));
        if (o2 && !!parsed.pr?.extensions?.bazaar !== !!o2?.extensions?.bazaar) f.push(F("X133", "info", `Only the ${parsed.pr?.extensions?.bazaar ? pm : other[0]} 402 carries the bazaar extension; crawlers that probe with ${parsed.pr?.extensions?.bazaar ? other[0] : pm} see no input/output schema.`, "Serve the same extensions on both 402s."));
        if (o2 && key(o2) !== key(parsed.pr)) f.push(F("X132", "warn", `GET and POST return different payment terms (network/payTo/amount/asset). Clients will see different prices depending on method.`));
      }
      // CORS: the 402 itself, then the preflight
      const acao = r.headers["access-control-allow-origin"];
      const expose = (r.headers["access-control-expose-headers"] ?? "").toLowerCase();
      if (acao && parsed.from === "header" && !expose.includes("payment-required") && expose !== "*") f.push(F("X009", "info", "CORS is on but PAYMENT-REQUIRED is not in access-control-expose-headers: browser-based agents cannot read the header challenge.", "Add access-control-expose-headers: PAYMENT-REQUIRED, PAYMENT-RESPONSE."));
      else if (!acao) f.push(F("X009", "info", "No CORS headers on the 402: in-browser agents cannot call this route (server-side agents are unaffected)."));
      if (pre.r && acao) {
        const ah = (pre.r.headers["access-control-allow-headers"] ?? "").toLowerCase();
        if (pre.r.status >= 400 || (ah && ah !== "*" && !/payment-signature|x-payment/.test(ah))) f.push(F("X009", "info", `CORS preflight (OPTIONS) ${pre.r.status >= 400 ? `returned ${pre.r.status}` : "does not allow the PAYMENT-SIGNATURE / X-PAYMENT request header"}: browser agents cannot send payment.`, "Allow PAYMENT-SIGNATURE (v2) and X-PAYMENT (v1) in access-control-allow-headers."));
      }
      // well-known cross-check
      if (wk.r?.status === 200) {
        const txt = dec.decode(wk.r.body).toLowerCase();
        const missing = [...new Set((parsed.pr.accepts ?? []).map((a: any) => String(a.payTo ?? "").toLowerCase()).filter(Boolean))].filter((x: any) => !txt.includes(x));
        if (missing.length && !/0x[0-9a-f]{40}/.test(txt)) f.push(F("X010", "info", "/.well-known/x402 exists but lists no payTo address, so it cannot be cross-checked against the live challenge.", undefined, "/.well-known/x402"));
        else if (missing.length) f.push(F("X010", "warn", `/.well-known/x402 exists but does not mention payTo ${missing.map((m: any) => m.slice(0, 10) + "…").join(", ")} from the live challenge.`, "Keep the well-known file and the live challenge in sync.", "/.well-known/x402"));
        // The reverse direction: addresses in the well-known file that this route's challenge does not use.
        // Fine if other routes use them; stale if they predate a payTo rotation (overwatch-dominion's question).
        const live = new Set((parsed.pr.accepts ?? []).map((a: any) => String(a.payTo ?? "").toLowerCase()));
        const wkAddrs = [...new Set(txt.match(/0x[0-9a-f]{40}(?![0-9a-f])/g) ?? [])];
        const assets = new Set([...KNOWN_ASSETS.keys(), ...(parsed.pr.accepts ?? []).map((a: any) => String(a.asset ?? "").toLowerCase())]);
        const extra = wkAddrs.filter((x) => !live.has(x) && !assets.has(x));
        if (!missing.length && extra.length) f.push(F("X010", "info", `/.well-known/x402 also lists ${extra.length} address(es) this route's challenge does not use (${extra.map((m) => m.slice(0, 10) + "…").join(", ")}). Fine if other routes pay to them; stale if they predate a payTo rotation.`, "Remove retired payTo addresses from the well-known file, or say which route each belongs to.", "/.well-known/x402"));
        probes.well_known_x402 = 200;
        probes.well_known_payto = missing.length ? (wkAddrs.length ? "mismatch" : "no_address") : "match";
      } else f.push(F("X010", "info", "No /.well-known/x402 (optional): a second place for agents to cross-check your payTo.", undefined, "/.well-known/x402"));
    }
  }
  const has = (x: typeof llms) => !!x.r && x.r.status === 200 && x.r.body.length > 20;
  probes.llms_txt = has(llms) ? 200 : (llms.r?.status ?? null);
  probes.openapi_json = has(oapi) ? 200 : (oapi.r?.status ?? null);
  if (!has(llms)) f.push(F("X011", "info", "No /llms.txt: agents reading docs have nothing to learn price, inputs and limits from.", undefined, "/llms.txt"));
  const alt = altAuth(openapiDoc(oapi), wk.r?.status === 200 ? dec.decode(wk.r.body) : null);
  if (alt.length) {
    probes.alt_auth = alt;
    f.push(F("X014", "info", `Documented non-x402 access: ${alt.join(", ")}. A caller holding these credentials may get 2xx with no 402 first; that is a second rail, not a missing payment path. This lint only sees the unauthenticated path.`, "Say in /.well-known/x402 or llms.txt which routes accept the alternate auth, so probes can tell 'credits path' from 'free leak'."));
  }
  if (!has(oapi)) f.push(F("X012", "info", "No /openapi.json: tools that auto-generate clients cannot see your request schema.", undefined, "/openapi.json"));
  f.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);
  let directories: DirResult[] | undefined;
  if (o.directories) {
    const parsed402 = r.status === 402 ? parsePaymentRequired(r.headers, r.body) : { pr: null, from: null };
    directories = directoryReadiness({ url: u.href, getStatus: g?.r?.status ?? null, postStatus: p?.r?.status ?? null, pr: parsed402.pr, challengeFrom: parsed402.from,
      lintErrors: f.filter((x) => x.severity === "error").length,
      openapiText: has(oapi) && !oapi.r!.truncated ? dec.decode(oapi.r!.body) : null, wellKnownText: wk.r?.status === 200 ? dec.decode(wk.r.body) : null });
  }
  return { url: u.href, verdict: verdictOf(f), summary, probes, ...(directories ? { directories } : {}), counts: { error: f.filter((x) => x.severity === "error").length, warn: f.filter((x) => x.severity === "warn").length, info: f.filter((x) => x.severity === "info").length }, findings: f, not_tested: NOT_TESTED, scope: SCOPE, verdict_meaning: VERDICT_MEANING, paid_path_checks: PAID_PATH_CHECKS };
}
