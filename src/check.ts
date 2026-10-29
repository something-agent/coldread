import "./crypto-tune";
/** ColdRead check: one report combining x402lint (challenge + discovery lint), ProofCheck (signed offers and
 *  signer authorization), an ERC-8004 identity lookup, and a labelled on-chain payer summary. The libraries are
 *  vendored source (src/vendor), not calls to the sibling Workers: a Worker cannot fetch another workers.dev
 *  Worker on the same account, and in-process code costs no extra subrequest. */
import { lintEndpoint } from "./vendor/x402lint/lint";
import { assertPublicUrl } from "./vendor/x402lint/safe";
import { probe } from "./vendor/proofcheck/probe";
import { readAgent, loadRegistration, IDENTITY_REGISTRY, CHAIN_RPCS } from "./vendor/proofcheck/chain";
import { wellKnownRegistration } from "./vendor/proofcheck/did";
import { payerSummary, BASE_USDC, BASE_CAIP2 } from "./payers";
import VERSIONS from "./vendor/VERSIONS.json";
import { canonicalize, sha256Hex } from "./canon";

export const SERVICE = { name: "ColdRead", version: "0.1.3", repo: "https://github.com/something-agent/coldread", operator: "something (an autonomous agent with an anonymous human operator)" };
export const REPORT_VERSION = "coldread/1";
export const SUBREQUEST_BUDGET = 45; // Workers Free: 50 per invocation, keep a margin for storage

export class BadRequest extends Error {}

/** Freshness: a fingerprint of the payment terms the report saw, so a buyer can tell at pay time whether the live
 *  challenge still matches the one that was checked (payTo rotation, price or asset change). Addresses lowercased,
 *  entries sorted by their JCS bytes, then sha256 over the JCS of the list. verify.mjs --live recomputes it. */
export const FINGERPRINT_ALGO = "sha256(JCS(sort_by_JCS([{scheme,network,asset:lower,pay_to:lower,amount:string}])))";
export const SUGGESTED_MAX_AGE_HOURS = 24;
export function termsList(accepts: any[]) {
  return (accepts ?? []).map((a) => ({ scheme: String(a?.scheme ?? ""), network: String(a?.network ?? ""), asset: lc(a?.asset), pay_to: lc(a?.pay_to ?? a?.payTo), amount: String(a?.amount ?? a?.maxAmountRequired ?? "") }))
    .map((t) => [canonicalize(t), t] as const).sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0)).map((x) => x[1]);
}
export async function termsFingerprint(accepts: any[]) { return sha256Hex(canonicalize(termsList(accepts))); }

export interface CheckInput { url: string; method?: "auto" | "GET" | "POST"; pay_to?: string; agent?: { chain_id: number; agent_id: string } }
type Sev = "red" | "amber" | "info" | "good";
export interface Signal { id: string; severity: Sev; part: string; text: string }

export const OVERALL_MEANING: Record<string, string> = {
  no_red_flags: "Nothing ColdRead checks looked wrong. This is not an endorsement and says nothing about settlement or delivery (see cannot_check).",
  attention: "At least one amber signal: read the signals before paying.",
  red_flags: "At least one red signal (malformed or contradictory payment terms, a bad signature, or an identity that does not match). Do not pay without resolving it.",
  unreachable: "The endpoint did not return a parseable x402 402 challenge, so there was nothing to judge.",
};
export const CANNOT_CHECK = [
  "whether a payment settles or the paid response is delivered (ColdRead never pays)",
  "the quality or truth of the paid content",
  "who controls the payTo wallet beyond the published bindings (did:web, DNS, ERC-8004) we can see",
  "payer history older than the stated window, and payments on networks other than Base USDC",
  "whether distinct payer wallets belong to distinct people",
  "anything that changed after checked_at",
];

export function parseInput(a: any): CheckInput {
  if (!a || typeof a !== "object") throw new BadRequest("body must be a JSON object");
  if (typeof a.url !== "string" || a.url.length > 2048) throw new BadRequest("url (string, http(s)) is required");
  try { assertPublicUrl(a.url, true); } catch (e) { throw new BadRequest(`url refused: ${(e as Error).message}`); }
  const method = a.method === undefined ? "auto" : String(a.method).toUpperCase() === "AUTO" ? "auto" : String(a.method).toUpperCase();
  if (!["auto", "GET", "POST"].includes(method)) throw new BadRequest("method must be auto, GET or POST");
  let pay_to: string | undefined;
  if (a.pay_to !== undefined) { if (!/^0x[0-9a-fA-F]{40}$/.test(String(a.pay_to))) throw new BadRequest("pay_to must be a 0x EVM address"); pay_to = String(a.pay_to).toLowerCase(); }
  let agent: CheckInput["agent"];
  const ag = a.agent ?? (a.agent_id !== undefined ? { chain_id: a.chain_id ?? 8453, agent_id: a.agent_id } : undefined);
  if (ag !== undefined) {
    const chain_id = Number(ag.chain_id ?? 8453), agent_id = String(ag.agent_id ?? "");
    if (!CHAIN_RPCS[chain_id]) throw new BadRequest(`agent.chain_id unsupported; supported: ${Object.keys(CHAIN_RPCS).join(", ")}`);
    if (!/^\d{1,30}$/.test(agent_id)) throw new BadRequest("agent.agent_id must be a decimal integer");
    agent = { chain_id, agent_id };
  }
  return { url: new URL(a.url).href, method: method as CheckInput["method"], pay_to, agent };
}

/** Wrap fetch with a subrequest counter so one check can never exceed the platform budget. */
export function budgetFetch(inner: typeof fetch, budget = SUBREQUEST_BUDGET) {
  const st = { used: 0, refused: 0 };
  const f = (async (input: any, init?: any) => {
    if (st.used >= budget) { st.refused++; throw new Error("ColdRead subrequest budget exhausted"); }
    st.used++;
    return inner(input, init);
  }) as typeof fetch;
  return { fetch: f, st };
}

const short = (e: unknown) => (e as Error)?.message?.slice(0, 160) ?? String(e);
const lc = (s: any) => String(s ?? "").toLowerCase();

async function erc8004Part(host: string, input: CheckInput, payTos: string[], f: typeof fetch) {
  let source: "caller_supplied" | "host_well_known" = "caller_supplied";
  let ref = input.agent;
  let hostListed: boolean | null = null;
  let wk: any = null;
  try { wk = await wellKnownRegistration(host, f); } catch (e) { wk = { _err: short(e) }; }
  const regs: any[] = Array.isArray(wk?.registrations) ? wk.registrations : [];
  const parsed = regs.map((r) => { const m = String(r?.agentRegistry ?? "").match(/^eip155:(\d+):(0x[0-9a-fA-F]{40})$/); return m ? { chain_id: Number(m[1]), registry: m[2].toLowerCase(), agent_id: String(r?.agentId ?? "") } : null; }).filter(Boolean) as { chain_id: number; registry: string; agent_id: string }[];
  const canonical = parsed.filter((p) => p.registry === IDENTITY_REGISTRY.toLowerCase() && CHAIN_RPCS[p.chain_id] && /^\d{1,30}$/.test(p.agent_id));
  if (ref) hostListed = wk?._err ? false : parsed.some((p) => p.chain_id === ref!.chain_id && p.agent_id === ref!.agent_id && p.registry === IDENTITY_REGISTRY.toLowerCase());
  else {
    const pick = canonical.find((p) => p.chain_id === 8453) ?? canonical[0];
    if (!pick) return { status: "none_published", source: "host_well_known", host, detail: wk?._err ? `no /.well-known/agent-registration.json (${wk._err})` : parsed.length ? "agent-registration.json lists no agent on the canonical ERC-8004 Identity Registry" : "agent-registration.json lists no registrations", ...(parsed.length && !canonical.length ? { other_registries: parsed.slice(0, 3) } : {}) };
    ref = { chain_id: pick.chain_id, agent_id: pick.agent_id }; source = "host_well_known"; hostListed = true;
  }
  const on = await readAgent(ref.chain_id, ref.agent_id, { fetchImpl: f });
  const out: any = { status: on.owner ? "found" : "not_found", source, host, chain_id: ref.chain_id, registry: IDENTITY_REGISTRY, agent_id: ref.agent_id, owner: on.owner, agent_wallet: on.agentWallet, agent_uri: on.agentURI?.startsWith("data:") ? on.agentURI.slice(0, 48) + "…(inline data URI)" : on.agentURI, host_lists_agent: hostListed };
  if (!on.owner) {
    const rpcDown = on.errors.length >= 3 && on.errors.every((e) => /rpc|fetch|timeout|abort|network|budget/i.test(e) && !/revert|execution|nonexistent|invalid token/i.test(e));
    if (rpcDown) { out.status = "rpc_error"; out.detail = "could not read the chain; unknown, not absent"; }
    return out;
  }
  const pts = payTos.map(lc);
  out.wallet_matches_pay_to = pts.length ? pts.includes(lc(on.agentWallet)) || pts.includes(lc(on.owner)) : null;
  out.matched_by = out.wallet_matches_pay_to ? (pts.includes(lc(on.agentWallet)) ? "agentWallet" : "owner") : null;
  if (on.agentURI) {
    try {
      const reg = await loadRegistration(on.agentURI, f);
      const services = Array.isArray(reg.services) ? reg.services : Array.isArray(reg.endpoints) ? reg.endpoints : [];
      const hosts = services.map((s: any) => { try { return new URL(String(s?.endpoint)).hostname.toLowerCase(); } catch { return null; } }).filter(Boolean);
      out.registration = { name: typeof reg.name === "string" ? reg.name.slice(0, 80) : undefined, x402_support: reg.x402Support ?? reg.x402support, active: reg.active, service_hosts: [...new Set(hosts)].slice(0, 8) };
      out.registration_lists_host = hosts.some((h: string) => h === host || h.endsWith("." + host) || host.endsWith("." + h));
    } catch (e) { out.registration_error = short(e); }
  }
  out.binding = hostListed && out.registration_lists_host !== false ? "two_way" : hostListed ? "host_only" : out.registration_lists_host ? "registration_only" : "none";
  out.binding_meaning = { two_way: "the host's agent-registration.json lists this agent and the registration names this host", host_only: "the host lists this agent, but the registration file does not name the host", registration_only: "the registration file names the host, but the host does not list this agent (anyone can name any host)", none: "nothing ties this agent to the host" }[out.binding as string];
  return out;
}

export const payerCacheKey = (payTos: string[]) => "p:" + [...new Set(payTos.map(lc))].sort().join(",");
export const PAYER_CACHE_MAX_AGE_H = 48;
export type PayerCache = (key: string) => Promise<{ computed_at: string; summary: any } | null>;

/** One part's output plus the subrequests it used. Parts never throw: failures come back as `error`. */
export interface PartOut { r?: any; error?: string; used: number; refused: number }
/** The four parts of a check. Locally they run in-process; on Workers each runs in its own invocation
 *  (self service binding) so each stays near the Free plan's 10 ms CPU limit. */
export interface Parts {
  lint(url: string, method: "auto" | "GET" | "POST"): Promise<PartOut>;
  probe(url: string, method: "GET" | "POST", nowSec: number): Promise<PartOut>;
  erc8004(host: string, input: CheckInput, payTos: string[]): Promise<PartOut>;
  payers(payTos: string[]): Promise<PartOut>;
}
export const PART_BUDGET = { lint: 14, probe: 11, erc8004: 8, payers: 9 };
const wrap = async (fn: () => Promise<any>, st: { used: number; refused: number }, s0 = { ...st }): Promise<PartOut> => {
  try { const r = await fn(); return { r, used: st.used - s0.used, refused: st.refused - s0.refused }; }
  catch (e) { return { error: short(e), used: st.used - s0.used, refused: st.refused - s0.refused }; }
};
/** Run one part with its own subrequest budget (used inside the per-part invocation). */
export function partRunner(inner: typeof fetch, shared?: { fetch: typeof fetch; st: { used: number; refused: number } }): Parts {
  const mk = (n: number) => shared ?? budgetFetch(inner, n);
  return {
    lint: (url, method) => { const b = mk(PART_BUDGET.lint); return wrap(() => lintEndpoint(url, { method, directories: true }, { fetchImpl: b.fetch }), b.st); },
    probe: (url, method, nowSec) => { const b = mk(PART_BUDGET.probe); return wrap(() => probe(url, { method }, { fetchImpl: b.fetch, cache: new Map(), now: nowSec }), b.st); },
    erc8004: (host, input, payTos) => { const b = mk(PART_BUDGET.erc8004); return wrap(() => erc8004Part(host, input, payTos, b.fetch), b.st); },
    payers: (payTos) => { const b = mk(PART_BUDGET.payers); return wrap(() => payerSummary(payTos, b.fetch), b.st); },
  };
}
/** Structured-clone safe copy (service-binding RPC results must not carry functions or class instances). */
export const plain = (x: any) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x, (_k, v) => (typeof v === "bigint" ? v.toString() : v instanceof Uint8Array ? Array.from(v) : v))));

export async function runCheck(input: CheckInput, o: { fetchImpl: typeof fetch; now?: Date; payerCache?: PayerCache; parts?: Parts; split?: string }) {
  const shared = budgetFetch(o.fetchImpl);
  const st = shared.st;
  const parts = o.parts ?? partRunner(o.fetchImpl, shared);
  const add = (x: PartOut) => { if (o.parts) { st.used += x.used + 1; st.refused += x.refused; } return x; };
  const t0 = Date.now();
  const checked_at = (o.now ?? new Date()).toISOString();
  const host = new URL(input.url).hostname.toLowerCase();
  const signals: Signal[] = [];
  const sig = (id: string, severity: Sev, part: string, text: string) => signals.push({ id, severity, part, text });

  // 1. x402lint: challenge shape + discovery
  const lo = add(await parts.lint(input.url, input.method ?? "auto"));
  const lint: any = lo.error ? { error: lo.error } : lo.r;
  const method: "GET" | "POST" = lint?.summary?.method === "POST" ? "POST" : lint?.summary?.method === "GET" ? "GET" : input.method === "POST" ? "POST" : "GET";

  // 2. ProofCheck probe (live accepts + signed offers + signer authorization)
  const po = add(await parts.probe(input.url, method, Math.floor((o.now ?? new Date()).getTime() / 1000)));
  const pr: any = po.error ? { error: po.error, is_402: false } : po.r;
  const accepts: any[] = Array.isArray(pr?.accepts) ? pr.accepts : [];
  const livePayTos = [...new Set(accepts.map((a) => lc(a.pay_to)).filter((x) => /^0x[0-9a-f]{40}$/.test(x)))];
  const basePayTos = [...new Set(accepts.filter((a) => a.network === BASE_CAIP2 && lc(a.asset) === BASE_USDC).map((a) => lc(a.pay_to)).filter((x) => /^0x[0-9a-f]{40}$/.test(x)))];
  const summaryPayTos = input.pay_to ? [input.pay_to] : basePayTos;

  // 3 + 4 in parallel: ERC-8004 identity, payer summary
  const [eo, pyo] = await Promise.all([parts.erc8004(host, input, livePayTos).then(add), parts.payers(summaryPayTos).then(add)]);
  const erc = eo.error ? { status: "error", detail: eo.error } : eo.r;
  let payers: any = pyo.r;
  if (pyo.error) {
    const live = pyo.error;
    const c = await o.payerCache?.(payerCacheKey(summaryPayTos)).catch(() => null);
    const age = c ? ((o.now ?? new Date()).getTime() - Date.parse(c.computed_at)) / 3.6e6 : Infinity;
    if (c && age >= 0 && age <= PAYER_CACHE_MAX_AGE_H) payers = { ...c.summary, status: "cached", source: { kind: "box_batch", computed_at: c.computed_at, age_hours: Math.round(age * 10) / 10, why: `live RPC from Cloudflare failed (${live.slice(0, 120)}); this summary was computed by ColdRead's batch job outside Cloudflare, over the window stated, ending at to_block` } };
    else payers = { status: "rpc_error", detail: live, pay_to: summaryPayTos, queued_for_batch: summaryPayTos.length > 0, retry_hint: summaryPayTos.length ? "the payTo is picked up by the batch job (runs at least daily); re-run the check later for a cached payer summary" : undefined };
  }

  // ---- signals
  const reachable = !!pr?.is_402 && accepts.length > 0;
  if (!reachable) sig("E000", "info", "endpoint", pr?.error ? `fetch failed: ${pr.error}` : `no parseable x402 challenge (HTTP ${pr?.http_status ?? "?"} on ${method})${pr?.notes?.length ? ": " + pr.notes[0] : ""}`);
  if (lint?.verdict === "fail") sig("E001", "red", "endpoint", `x402lint found ${lint.counts.error} error(s) in the 402 challenge: ${lint.findings.filter((x: any) => x.severity === "error").slice(0, 2).map((x: any) => `${x.id} ${x.message ?? x.msg ?? ""}`.trim()).join("; ")}`);
  else if (lint?.verdict === "warn") sig("E002", "amber", "endpoint", `x402lint: ${lint.counts.warn} warning(s): ${lint.findings.filter((x: any) => x.severity === "warn").slice(0, 2).map((x: any) => `${x.id} ${x.message ?? x.msg ?? ""}`.trim()).join("; ")}`);
  else if (lint?.verdict === "ok") sig("E003", "good", "endpoint", "x402lint: the unpaid 402 challenge and discovery look well-formed (unpaid path only)");
  if (lint?.probes?.well_known_payto === "mismatch") sig("E004", "amber", "endpoint", "/.well-known/x402 does not list the payTo the live challenge uses");
  if (input.pay_to && reachable && !livePayTos.includes(input.pay_to)) sig("E005", "red", "endpoint", `the payTo you expected (${input.pay_to}) is not in the live challenge (${livePayTos.join(", ") || "none"})`);
  const off = pr?.offer_receipt;
  if (off?.has_offer_receipt_extension) {
    const v = (off.results ?? []).map((r: any) => r.verdict);
    if (v.some((x: string) => x === "invalid_signature" || x === "rejected")) sig("S001", "red", "signed_offers", `a signed offer failed verification (${v.join(", ")})`);
    else if (v.length && v.every((x: string) => x === "valid_authorized")) {
      const roots = Math.max(...(off.results ?? []).map((r: any) => r.authorization?.independent_roots?.count ?? 0));
      sig("S002", "good", "signed_offers", `signed offer(s) verify and the signer is bound to the domain or payTo (${roots} independent root(s) of trust)`);
    } else if (v.includes("valid_signer_unproven")) sig("S003", "amber", "signed_offers", "signed offer verifies but nothing independent ties the key to this domain");
  } else if (reachable) sig("S000", "info", "signed_offers", "no signed offers (x402 offer-receipt extension is optional); the terms are not signed");
  const e: any = erc;
  if (e.status === "found") {
    if (e.wallet_matches_pay_to === false) sig("I001", e.source === "caller_supplied" ? "red" : "amber", "erc8004", `ERC-8004 agent ${e.agent_id} (chain ${e.chain_id}) has wallet ${e.agent_wallet ?? "unset"} and owner ${e.owner}; neither is the live payTo`);
    if (e.binding === "registration_only" || e.binding === "none") sig("I002", e.source === "caller_supplied" ? "amber" : "info", "erc8004", `ERC-8004 agent ${e.agent_id} is not tied to ${host} by the host's agent-registration.json`);
    if (e.wallet_matches_pay_to && (e.binding === "two_way" || e.binding === "host_only")) sig("I003", "good", "erc8004", `ERC-8004 agent ${e.agent_id} (chain ${e.chain_id}) is listed by the host and its ${e.matched_by} is the live payTo`);
  } else if (e.status === "not_found" && e.source === "caller_supplied") sig("I004", "red", "erc8004", `ERC-8004 agent ${e.agent_id} does not exist on chain ${e.chain_id}`);
  else if (e.status === "not_found") sig("I005", "amber", "erc8004", `${host} lists ERC-8004 agent ${e.agent_id} but it does not exist on chain ${e.chain_id}`);
  else if (e.status === "none_published") sig("I000", "info", "erc8004", "no ERC-8004 identity published by the host");
  const p: any = payers;
  if (p.status === "cached") sig("P009", "info", "payers", `payer summary is from ColdRead's batch job at ${p.source.computed_at} (${p.source.age_hours} h before this check), not live`);
  if (p.status === "ok" || p.status === "partial" || p.status === "cached") {
    const inb = p.inbound.transfers;
    if (inb === 0) sig("P000", "info", "payers", `no USDC received on Base by the payTo in the last ~${p.window.approx_hours} h`);
    else {
      const lab = p.by_label;
      const nonDemand = lab.self.transfers + lab.known_sweeper.transfers + lab.broad_payer.transfers;
      if (lab.repeat_or_narrow.transfers === 0 && nonDemand === inb) sig("P001", "amber", "payers", `all ${inb} inbound USDC transfers in ~${p.window.approx_hours} h came from the payTo itself, documented sweepers or broad payers: no sign of chosen buyers`);
      else if (lab.self.transfers / inb > 0.5) sig("P002", "amber", "payers", `${lab.self.transfers} of ${inb} inbound transfers are self-payments`);
      else sig("P003", "info", "payers", `${inb} inbound USDC transfers from ${p.inbound.distinct_payers} payer(s) in ~${p.window.approx_hours} h; by transfers: ${lab.repeat_or_narrow.transfers} narrow/repeat (not proven independent), ${nonDemand} self/sweeper/broad, ${lab.unclassified.transfers} unclassified${p.note ? " (classification query failed; queued for the batch job)" : ""}`);
    }
  }
  const sevs = signals.map((s) => s.severity);
  const overall = !reachable ? "unreachable" : sevs.includes("red") ? "red_flags" : sevs.includes("amber") ? "attention" : "no_red_flags";
  const cannot = [...CANNOT_CHECK];
  if (lint?.error) cannot.push(`x402lint did not run: ${lint.error}`);
  if (p.status === "rpc_error") cannot.push(`payer summary unavailable: ${p.detail ?? "RPC error"}`);
  if (e.status === "rpc_error" || e.status === "error") cannot.push(`ERC-8004 lookup unavailable: ${e.detail ?? "RPC error"}`);
  if (st.refused) cannot.push(`${st.refused} lookup(s) skipped: subrequest budget reached`);

  const signers = [...new Set(((off?.results ?? []) as any[]).map((r) => lc(r.signer)).filter(Boolean))];
  const freshness = {
    checked_at,
    terms_fingerprint: reachable ? { algo: FINGERPRINT_ALGO, hex: await termsFingerprint(accepts), entries: accepts.length } : null,
    challenge_pay_tos: livePayTos,
    offer_signers: signers,
    suggested_max_age_hours: SUGGESTED_MAX_AGE_HOURS,
    stale_if: [
      "the live challenge's terms fingerprint differs (payTo, price, asset, network or scheme changed): re-run the check before paying",
      "a signed offer is now signed by a key not in offer_signers, or a listed key was revoked",
      `checked_at is older than suggested_max_age_hours (${SUGGESTED_MAX_AGE_HOURS} h); payer history and identity bindings drift`,
    ],
    how_to_compare: "node verify.mjs <report> --live  (re-fetches the subject's unpaid 402, recomputes the fingerprint and reports age; never pays)",
  };

  const report = {
    report_version: REPORT_VERSION,
    report_id: crypto.randomUUID(),
    subject: { url: input.url, host, method, ...(input.pay_to ? { expected_pay_to: input.pay_to } : {}), ...(input.agent ? { agent: input.agent } : {}) },
    checked_at,
    service: { ...SERVICE, libraries: VERSIONS },
    overall,
    overall_meaning: OVERALL_MEANING[overall],
    signals,
    parts: {
      endpoint: lint?.error ? { error: lint.error } : { verdict: lint.verdict, verdict_meaning: lint.verdict_meaning, summary: lint.summary, probes: lint.probes, counts: lint.counts, findings: lint.findings.slice(0, 20).map((x: any) => ({ id: x.id, severity: x.severity, message: x.message ?? x.msg, ...(x.where ? { where: x.where } : {}) })), directories: lint.directories },
      live_challenge: { http_status: pr?.http_status ?? null, final_url: pr?.final_url, x402_version: pr?.x402_version ?? null, accepts, extensions: pr?.extensions ?? [], ...(pr?.error ? { error: pr.error } : {}) },
      signed_offers: off ? { has_extension: off.has_offer_receipt_extension, offers_found: off.offers_found, offers_checked: off.offers_checked, results: (off.results ?? []).map((r: any) => ({ format: r.format, verdict: r.verdict, signer: r.signer, authorization: { status: r.authorization?.status, independent_roots: r.authorization?.independent_roots, evidence: (r.authorization?.evidence ?? []).map((x: any) => ({ method: x.method, result: x.result, strength: x.strength, detail: String(x.detail ?? "").slice(0, 200) })) }, summary: r.summary })) } : { has_extension: false },
      erc8004: erc,
      payers,
    },
    freshness,
    cannot_check: cannot,
    method_notes: { subrequests_used: st.used, elapsed_ms: Date.now() - t0, execution: o.parts ? (o.split ?? "split: lint, probe, erc8004 and payers each ran in a separate Worker invocation (self service binding) to stay near the Free plan CPU limit") : "single process", never_pays: true, never_signs_payments: true },
  };
  return report;
}
