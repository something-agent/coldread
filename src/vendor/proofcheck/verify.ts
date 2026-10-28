/** Verification of x402 offer-receipt artifacts (EIP-712 and JWS) with graded signer-authorization evidence. */
import { isAddress, lc } from "./bytes";
import { Evidence, applyRevocation, Signer, gatherEvidence, sameKey, summarize, independentRoots } from "./auth";
import { offerDigest, receiptDigest, recoverSigner, OfferPayload, ReceiptPayload } from "./eip712";
import { parseJws, verifyJwsFast, PubKey } from "./jws";
import { resolveKid } from "./did";
import { hostOf } from "./util";

export const TRUST_ROOT = "strong = bound to whoever controls the host today (its web server or DNS, the same root as TLS) or to an ERC-8004 agent the host itself lists. It does not mean the host is uncompromised: a hijacked domain grades its own keys strong. ProofCheck catches keys the host never vouched for, not keys the host vouches for wrongly.";
export interface Check { id: string; status: "pass" | "fail" | "warn" | "info"; detail: string }
export type Verdict = "valid_authorized" | "valid_signer_unproven" | "rejected" | "invalid_signature";

export interface Ctx { fetchImpl?: typeof fetch; now?: number; skipNetwork?: boolean; cache?: Map<string, Promise<Evidence[]>> }
export interface ArtifactResult {
  kind: "offer" | "receipt"; format: string; verdict: Verdict; signature_valid: boolean;
  signer: { address?: string; kid?: string; key_type?: string } | null;
  payload: unknown; checks: Check[]; authorization: { status: "authorized" | "weak_only" | "unproven"; host: string | null; evidence: Evidence[]; checked_at?: string; time_scope?: string; trust_root?: string; independent_roots?: { count: number; roots: string[]; note: string } };
  summary: string;
}

const now = (c: Ctx) => c.now ?? Math.floor(Date.now() / 1000);
const pass = (id: string, detail: string): Check => ({ id, status: "pass", detail });
const fail = (id: string, detail: string): Check => ({ id, status: "fail", detail });
const warn = (id: string, detail: string): Check => ({ id, status: "warn", detail });
const info = (id: string, detail: string): Check => ({ id, status: "info", detail });

const sameUrl = (a: string, b: string) => { try { const x = new URL(a), y = new URL(b); return x.origin === y.origin && x.pathname.replace(/\/$/, "") === y.pathname.replace(/\/$/, "") && x.search === y.search; } catch { return a === b; } };

interface RawArtifact { format?: string; payload?: any; signature?: string; acceptIndex?: number }

/** Recover signer + validate signature. Returns signer identity, the payload as signed, and any errors. */
async function checkSignature(kind: "offer" | "receipt", art: RawArtifact, ctx: Ctx): Promise<{ ok: boolean; payload: any; signer: Signer | null; ident: ArtifactResult["signer"]; checks: Check[]; kidDomain?: string; kidMethod?: string }> {
  const checks: Check[] = [];
  const format = art.format;
  if (format === "eip712") {
    if (!art.payload || typeof art.payload !== "object") return { ok: false, payload: null, signer: null, ident: null, checks: [fail("shape", "eip712 artifact needs a payload object")] };
    if (typeof art.signature !== "string") return { ok: false, payload: art.payload, signer: null, ident: null, checks: [fail("shape", "missing signature")] };
    try {
      const digest = kind === "offer" ? offerDigest(art.payload as OfferPayload) : receiptDigest(art.payload as ReceiptPayload);
      const { signer, highS } = recoverSigner(digest, art.signature);
      checks.push(pass("signature", `EIP-712 signature recovers to ${signer}`));
      if (highS) checks.push(warn("signature_malleable", "signature has a high-S value (malleable form); valid but non-canonical"));
      return { ok: true, payload: art.payload, signer: { evm: signer }, ident: { address: signer, key_type: "secp256k1" }, checks };
    } catch (e) { return { ok: false, payload: art.payload, signer: null, ident: null, checks: [fail("signature", `cannot verify: ${(e as Error).message}`)] }; }
  }
  if (format === "jws") {
    if (typeof art.signature !== "string") return { ok: false, payload: null, signer: null, ident: null, checks: [fail("shape", "jws artifact needs the compact JWS in 'signature'")] };
    if (art.payload !== undefined) checks.push(warn("jws_payload_present", "spec says payload MUST be omitted for JWS; ignoring it and using the signed payload"));
    try {
      const p = parseJws(art.signature);
      const kid = p.header.kid;
      if (typeof kid !== "string") return { ok: false, payload: p.payload, signer: null, ident: null, checks: [fail("jws_header", "JWS header has no kid")] };
      if (p.header.crit) checks.push(warn("jws_crit", "JWS has a 'crit' header; not processed"));
      let res: Awaited<ReturnType<typeof resolveKid>>;
      try { res = await resolveKid(kid, ctx.fetchImpl); } catch (e) { return { ok: false, payload: p.payload, signer: null, ident: { kid }, checks: [fail("kid_resolution", `cannot resolve kid: ${(e as Error).message}`)] }; }
      let matched: PubKey | null = null; let lastReason = "";
      for (const k of res.keys) { const v = await verifyJwsFast(p, k); if (v.ok) { matched = k; break; } lastReason = v.reason ?? lastReason; }
      if (!matched) return { ok: false, payload: p.payload, signer: null, ident: { kid }, checks: [fail("signature", `JWS (${p.header.alg}) did not verify against ${res.keys.length} key(s) from ${res.method}${lastReason ? `: ${lastReason}` : ""}`)] };
      checks.push(pass("signature", `JWS ${p.header.alg} verifies with key from ${kid}`));
      return { ok: true, payload: p.payload, signer: { evm: matched.evmAddress, pub: matched }, ident: { kid, address: matched.evmAddress, key_type: matched.kind }, checks, kidDomain: res.domain, kidMethod: res.method };
    } catch (e) { return { ok: false, payload: null, signer: null, ident: null, checks: [fail("jws_parse", (e as Error).message)] }; }
  }
  return { ok: false, payload: null, signer: null, ident: null, checks: [fail("format", `unknown format '${String(format)}' (expected eip712 or jws)`)] };
}

async function authorize(signer: Signer, host: string | null, o: { payTo?: string; trustedPayTo?: string[]; agent?: any; kidDomain?: string; kidMethod?: string; signedAt?: number }, ctx: Ctx): Promise<ArtifactResult["authorization"]> {
  if (!host) return { status: "unproven", host: null, evidence: [{ method: "host", result: "error", detail: "resourceUrl has no usable host" }] };
  const key = JSON.stringify([signer.evm?.toLowerCase(), signer.pub ? Array.from(signer.pub.bytes).join(",") : "", host, o.trustedPayTo, o.agent, o.signedAt]);
  const run = async (): Promise<Evidence[]> => {
    const ev = await gatherEvidence(signer, host, { payTo: o.payTo, trustedPayTo: o.trustedPayTo, agent: o.agent, skipNetwork: ctx.skipNetwork, signedAt: o.signedAt }, ctx);
    if (o.kidMethod === "did:web" && o.kidDomain) {
      const bound = o.kidDomain === host;
      const i = ev.findIndex((e) => e.method === "did_web");
      const e0: Evidence = { method: "did_web", result: bound ? "authorized" : "not_found", strength: bound ? "strong" : undefined, detail: bound ? `kid resolved from https://${o.kidDomain} (the resource's own domain)` : `kid resolves on ${o.kidDomain}, which is not the resource host ${host}`, source: `did:web:${o.kidDomain}` };
      const e = applyRevocation(e0, signer.pub?.revoked, o.signedAt);
      if (i >= 0) ev[i] = bound || ev[i].result !== "authorized" ? e : ev[i]; else ev.push(e);
    }
    return ev;
  };
  let p: Promise<Evidence[]>;
  if (ctx.cache) { p = ctx.cache.get(key) ?? run(); ctx.cache.set(key, p); } else p = run();
  const evidence = await p;
  return { status: summarize(evidence), host, evidence, checked_at: new Date(now(ctx) * 1000).toISOString(),
    time_scope: "current state at checked_at, not at issuance: DID/DNS/registration may have changed since the artifact was signed. Store this result (and checked_at) beside the artifact if you need quote-time attribution.",
    trust_root: TRUST_ROOT, independent_roots: independentRoots(evidence) };
}

function verdictOf(sigOk: boolean, checks: Check[], auth: ArtifactResult["authorization"]): Verdict {
  if (!sigOk) return "invalid_signature";
  if (checks.some((c) => c.status === "fail")) return "rejected";
  return auth.status === "authorized" ? "valid_authorized" : "valid_signer_unproven";
}
const SUMMARY: Record<Verdict, string> = {
  valid_authorized: "Signature is valid and the signer is bound to the resource's domain (or to its live payTo).",
  valid_signer_unproven: "Signature is valid, but no independent evidence ties this key to the resource. Do not treat the offer/receipt as proof the service issued it.",
  rejected: "Signature verifies, but one or more consistency checks failed (see checks).",
  invalid_signature: "The signature does not verify.",
};

export interface OfferOpts { accepts?: any[]; resourceUrl?: string; trustedPayTo?: string[]; agent?: { chainId: number; agentId: string; registry?: string } }

export async function verifyOffer(art: RawArtifact, o: OfferOpts, ctx: Ctx): Promise<ArtifactResult> {
  const s = await checkSignature("offer", art, ctx);
  const checks = [...s.checks];
  const p = s.payload ?? {};
  const host = typeof p.resourceUrl === "string" ? hostOf(p.resourceUrl) : null;
  if (s.ok) {
    if (p.version !== 1) checks.push(fail("version", `payload.version is ${String(p.version)}; only version 1 is defined`)); else checks.push(pass("version", "version 1"));
    if (!/^eip155:\d+$/.test(String(p.network))) checks.push(warn("network_format", `network '${String(p.network)}' is not CAIP-2 eip155:<id>`));
    if (art.format === "eip712" && !isAddress(p.payTo)) checks.push(warn("payTo_format", "payTo is not a valid EVM address"));
    if ((typeof p.validUntil === "number" || typeof p.validUntil === "string") && Number(p.validUntil) !== 0) {
      const vu = Number(p.validUntil);
      checks.push(now(ctx) > vu ? fail("expiry", `offer expired ${now(ctx) - vu}s ago (validUntil ${vu})`) : pass("expiry", `valid for another ${vu - now(ctx)}s`));
    } else checks.push(warn("expiry", "offer has no validUntil; it never expires, so a leaked offer is replayable indefinitely"));
    if (o.resourceUrl) checks.push(sameUrl(o.resourceUrl, p.resourceUrl) ? pass("resource_match", "payload.resourceUrl equals the URL you checked") : fail("resource_match", `payload.resourceUrl (${String(p.resourceUrl)}) differs from ${o.resourceUrl}: offer was signed for a different resource`));
    if (Array.isArray(o.accepts)) {
      const hit = o.accepts.findIndex((a: any) => a && lc(String(a.network)) === lc(String(p.network)) && lc(String(a.asset)) === lc(String(p.asset)) && lc(String(a.payTo)) === lc(String(p.payTo)) && String(a.amount ?? a.maxAmountRequired) === String(p.amount) && String(a.scheme) === String(p.scheme));
      if (hit < 0) checks.push(fail("accepts_match", "no accepts[] entry matches the signed network/asset/payTo/amount/scheme: the signed terms differ from the terms you would pay"));
      else {
        checks.push(pass("accepts_match", `matches accepts[${hit}]`));
        if (typeof art.acceptIndex === "number" && art.acceptIndex !== hit) checks.push(warn("accept_index", `unsigned acceptIndex says ${art.acceptIndex} but terms match accepts[${hit}] (spec: match on fields, not index)`));
      }
    }
  }
  let authz: ArtifactResult["authorization"] = { status: "unproven", host, evidence: [] };
  if (s.ok && s.signer) {
    const trusted = [...(o.trustedPayTo ?? []), ...(Array.isArray(o.accepts) ? o.accepts.map((a: any) => a?.payTo).filter(isAddress) : [])];
    authz = await authorize(s.signer, host, { payTo: isAddress(p.payTo) ? p.payTo : undefined, trustedPayTo: trusted.length ? trusted : undefined, agent: o.agent, kidDomain: s.kidDomain, kidMethod: s.kidMethod, signedAt: Number.isFinite(Number(p.issuedAt)) && p.issuedAt !== undefined ? Number(p.issuedAt) : undefined }, ctx);
    if (o.accepts && !o.trustedPayTo) checks.push(info("payTo_trust", "payTo was taken from the accepts[] you supplied; strong only if those came from the resource's live 402"));
  }
  const verdict = verdictOf(s.ok, checks, authz);
  return { kind: "offer", format: String(art.format), verdict, signature_valid: s.ok, signer: s.ident, payload: s.payload, checks, authorization: authz, summary: SUMMARY[verdict] };
}

export interface ReceiptOpts { resourceUrl?: string; payer?: string; transaction?: string; network?: string; maxAgeSeconds?: number; trustedPayTo?: string[]; agent?: { chainId: number; agentId: string; registry?: string } }

export async function verifyReceipt(art: RawArtifact, o: ReceiptOpts, ctx: Ctx): Promise<ArtifactResult> {
  const s = await checkSignature("receipt", art, ctx);
  const checks = [...s.checks];
  const p = s.payload ?? {};
  const host = typeof p.resourceUrl === "string" ? hostOf(p.resourceUrl) : null;
  if (s.ok) {
    if (p.version !== 1) checks.push(fail("version", `payload.version is ${String(p.version)}; only version 1 is defined`)); else checks.push(pass("version", "version 1"));
    const issued = Number(p.issuedAt);
    if (!Number.isFinite(issued)) checks.push(fail("issued_at", "issuedAt is not a number"));
    else {
      const age = now(ctx) - issued, max = o.maxAgeSeconds ?? 3600;
      if (age < -120) checks.push(fail("issued_at", `receipt claims to be issued ${-age}s in the future`));
      else if (age > max) checks.push(warn("issued_at", `receipt is ${age}s old (policy max ${max}s); fine for audit, stale for live gating`));
      else checks.push(pass("issued_at", `issued ${Math.max(age, 0)}s ago`));
    }
    if (o.resourceUrl) checks.push(sameUrl(o.resourceUrl, p.resourceUrl) ? pass("resource_match", "resourceUrl matches") : fail("resource_match", `receipt is for ${String(p.resourceUrl)}, not ${o.resourceUrl}`));
    if (o.payer) checks.push(lc(String(p.payer)) === lc(o.payer) ? pass("payer_match", "payer matches") : fail("payer_match", `receipt payer ${String(p.payer)} != expected ${o.payer}`));
    if (o.network) checks.push(lc(String(p.network)) === lc(o.network) ? pass("network_match", "network matches") : fail("network_match", `receipt network ${String(p.network)} != ${o.network}`));
    if (o.transaction) checks.push(lc(String(p.transaction ?? "")) === lc(o.transaction) ? pass("transaction_match", "transaction hash matches the settlement") : fail("transaction_match", `receipt transaction '${String(p.transaction ?? "")}' != settlement ${o.transaction}`));
    if (p.transaction) checks.push(info("transaction", `receipt references tx ${String(p.transaction)}; to confirm the amount actually landed on-chain use StillCurrent /verify/payment (paid) or any block explorer`));
    else checks.push(info("transaction", "privacy-minimal receipt (no transaction hash): proves the server says it served this payer, not that funds moved"));
  }
  let authz: ArtifactResult["authorization"] = { status: "unproven", host, evidence: [] };
  if (s.ok && s.signer) authz = await authorize(s.signer, host, { trustedPayTo: o.trustedPayTo, agent: o.agent, kidDomain: s.kidDomain, kidMethod: s.kidMethod, signedAt: Number.isFinite(Number(p.issuedAt)) && p.issuedAt !== undefined ? Number(p.issuedAt) : undefined }, ctx);
  const verdict = verdictOf(s.ok, checks, authz);
  return { kind: "receipt", format: String(art.format), verdict, signature_valid: s.ok, signer: s.ident, payload: s.payload, checks, authorization: authz, summary: SUMMARY[verdict] };
}

/** Verify every signed offer in a PaymentRequired object. Authorization lookups are de-duplicated per signer. */
export async function verifyPaymentRequired(pr: any, o: { resourceUrl?: string; maxOffers?: number }, ctx: Ctx) {
  const ext = pr?.extensions?.["offer-receipt"];
  const offers: RawArtifact[] = Array.isArray(ext?.info?.offers) ? ext.info.offers : [];
  const accepts = Array.isArray(pr?.accepts) ? pr.accepts : undefined;
  const c: Ctx = { ...ctx, cache: ctx.cache ?? new Map() };
  const cap = Math.min(o.maxOffers ?? 4, 4); // ~2ms CPU per secp256k1 recovery; Workers Free allows 10ms CPU
  const results: ArtifactResult[] = [];
  for (const off of offers.slice(0, cap)) results.push(await verifyOffer(off, { accepts, resourceUrl: o.resourceUrl ?? pr?.resource?.url }, c));
  return { has_offer_receipt_extension: !!ext, offers_found: offers.length, offers_checked: results.length, truncated: offers.length > cap, results };
}
export { sameKey };
