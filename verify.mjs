#!/usr/bin/env node
// ColdRead report verifier. No dependencies; Node >= 18.
//   node verify.mjs report.json            verify a saved envelope
//   node verify.mjs https://.../v1/report/<digest>
//   node verify.mjs report.json --online   also compare against the live /.well-known/coldread-keys.json
//   node verify.mjs report.json --live     also re-fetch the subject's unpaid 402 and compare its payment-terms
//                                          fingerprint with report.freshness (stale or not; never pays)
// Checks: (1) sha256 over the JCS (RFC 8785) bytes of envelope.report equals envelope.digest.hex,
//         (2) the Ed25519 signature over "coldread-report-v1:" + digest verifies,
//         (3) the signing key is one of ColdRead's published keys (pinned below) and not revoked at checked_at.
// Exit code 0 = valid, 1 = invalid, 2 = usage or fetch error.
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const PINNED = [{ kid: "coldread-2026-10-28", public_key: "UMbgYt761I-KAv3efV6JFtBAzcpw_wLvNmkbMt67M-4", revoked_at: null }];
const KEYS_URL = "https://coldread.something-agent.workers.dev/.well-known/coldread-keys.json";
const PREFIX = "coldread-report-v1:";

export function canonicalize(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isFinite(v)) throw new Error("JCS: non-finite number"); return JSON.stringify(v); }
  if (Array.isArray(v)) return "[" + v.map((x) => (x === undefined ? "null" : canonicalize(x))).join(",") + "]";
  if (typeof v === "object") { const ks = Object.keys(v).filter((k) => v[k] !== undefined).sort(); return "{" + ks.map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}"; }
  throw new Error("JCS: unsupported type " + typeof v);
}

export function verifyReport(env, keys = PINNED) {
  const problems = [];
  if (!env?.report) return { valid: false, problems: ["not a ColdRead envelope"] };
  const hex = createHash("sha256").update(canonicalize(env.report), "utf8").digest("hex");
  const digest_ok = hex === env.digest?.hex;
  if (!digest_ok) problems.push("digest mismatch: report changed after signing");
  const s = env.signature ?? {};
  let signature_ok = false;
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: s.public_key }, format: "jwk" });
    signature_ok = verify(null, Buffer.from(PREFIX + hex, "utf8"), key, Buffer.from(s.value, "base64url"));
  } catch (e) { problems.push("signature unreadable: " + e.message); }
  if (!signature_ok) problems.push("signature does not verify");
  const k = keys.find((x) => x.kid === s.key_id && x.public_key === s.public_key);
  let key_ok = !!k;
  if (!k) problems.push("signing key is not a published ColdRead key");
  else if (k.revoked_at && String(env.report.checked_at) >= k.revoked_at) { key_ok = false; problems.push("key revoked at " + k.revoked_at); }
  return { valid: digest_ok && signature_ok && key_ok, digest: hex, digest_ok, signature_ok, key_ok, key_id: s.key_id, checked_at: env.report.checked_at, subject: env.report.subject?.url, overall: env.report.overall, problems };
}

const lc = (x) => String(x ?? "").toLowerCase();
export function termsList(accepts) {
  return (accepts ?? []).map((a) => ({ scheme: String(a?.scheme ?? ""), network: String(a?.network ?? ""), asset: lc(a?.asset), pay_to: lc(a?.pay_to ?? a?.payTo), amount: String(a?.amount ?? a?.maxAmountRequired ?? "") }))
    .map((t) => [canonicalize(t), t]).sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0)).map((x) => x[1]);
}
export const termsFingerprint = (accepts) => createHash("sha256").update(canonicalize(termsList(accepts)), "utf8").digest("hex");

/** Parse an x402 402 response (v2 PAYMENT-REQUIRED header, base64 JSON; or a JSON body) into its accepts list. */
export function acceptsFrom(headers, bodyText) {
  const h = headers.get?.("payment-required") ?? headers["payment-required"];
  if (h) { try { return JSON.parse(Buffer.from(h, "base64").toString("utf8")).accepts ?? []; } catch {} }
  try { return JSON.parse(bodyText).accepts ?? []; } catch { return []; }
}

export function compareFreshness(report, liveAccepts, now = new Date()) {
  const f = report?.freshness;
  const age_hours = Math.round(((now.getTime() - Date.parse(report?.checked_at)) / 3.6e6) * 10) / 10;
  if (!f?.terms_fingerprint?.hex) return { comparable: false, age_hours, note: "report has no terms fingerprint (made before ColdRead 0.1.2, or the endpoint was unreachable)" };
  const live = termsFingerprint(liveAccepts);
  const same = live === f.terms_fingerprint.hex;
  const too_old = age_hours > (f.suggested_max_age_hours ?? 24);
  return { comparable: true, terms_match: same, report_fingerprint: f.terms_fingerprint.hex, live_fingerprint: live, live_pay_tos: [...new Set(termsList(liveAccepts).map((t) => t.pay_to))], age_hours, stale: !same || too_old, why: !same ? "live payment terms differ from the checked ones: re-run the check before paying" : too_old ? "terms unchanged, but the report is older than suggested_max_age_hours" : "terms unchanged and within the suggested age" };
}

// Standalone EVM addresses in a /.well-known/x402 file: JSON string values that are exactly an address, or for
// non-JSON text a 40-hex run not adjacent to hex or URL-query characters (same rule as x402lint 0.2.3+).
export function discoveryAddresses(text) {
  const out = new Set();
  try {
    const walk = (v) => { if (typeof v === "string") { if (/^0x[0-9a-fA-F]{40}$/.test(v.trim())) out.add(v.trim().toLowerCase()); } else if (v && typeof v === "object") Object.values(v).forEach(walk); };
    walk(JSON.parse(text));
  } catch {
    for (const m of String(text).matchAll(/(?<![0-9a-zA-Z=&?\/])0x[0-9a-fA-F]{40}(?![0-9a-zA-Z])/g)) out.add(m[0].toLowerCase());
  }
  return [...out];
}

// 0.1.4 (cinnabar): compare the host's live /.well-known/x402 addresses with the live challenge and the report.
// Stale only on a conflict (the file lists addresses and none is a live payTo); a changed list alone is reported, not stale.
export function compareDiscovery(report, liveDiscovery, livePayTos) {
  const rec = report?.freshness?.discovery_pay_tos;
  if (liveDiscovery == null) return { comparable: false, note: "no /.well-known/x402 on the host now" + (rec?.length ? " (the report recorded " + rec.length + " address(es))" : "") };
  const live = new Set(liveDiscovery); const pays = (livePayTos ?? []).map((x) => String(x).toLowerCase());
  const conflict = live.size > 0 && pays.length > 0 && !pays.some((p) => live.has(p));
  const changed = Array.isArray(rec) ? (rec.length !== live.size || rec.some((x) => !live.has(x))) : null;
  return { comparable: true, report_discovery_pay_tos: rec ?? null, live_discovery_pay_tos: [...live], conflict, changed, stale: conflict,
    why: conflict ? "the well-known file lists payTo addresses but none matches the live challenge: re-run the check before paying" : changed ? "discovery addresses changed since the report, but the live payTo is still listed (or none listed): informational" : "discovery consistent with the live challenge" };
}

async function main() {
  const args = process.argv.slice(2);
  const src = args.find((a) => !a.startsWith("--"));
  const flag = args.includes("--online") ? "--online" : undefined;
  if (!src) { console.error("usage: node verify.mjs <report.json | report URL> [--online]"); process.exit(2); }
  const ua = { headers: { "user-agent": "coldread-verify/1" } };
  let env;
  try { env = /^https?:\/\//.test(src) ? await (await fetch(src, ua)).json() : JSON.parse(readFileSync(src, "utf8")); }
  catch (e) { console.error("cannot read report: " + e.message); process.exit(2); }
  let keys = PINNED;
  if (flag === "--online") {
    try {
      const live = (await (await fetch(KEYS_URL, ua)).json()).keys;
      for (const p of PINNED) if (!live.some((l) => l.kid === p.kid && l.public_key === p.public_key)) console.error("warning: pinned key " + p.kid + " is not in the live key list");
      keys = live;
    } catch (e) { console.error("cannot fetch live keys: " + e.message); process.exit(2); }
  }
  const r = verifyReport(env, keys);
  if (args.includes("--live") && env?.report?.subject?.url) {
    try {
      const m = env.report.subject.method === "POST" ? "POST" : "GET";
      const res = await fetch(env.report.subject.url, { method: m, headers: { "user-agent": "coldread-verify/1", ...(m === "POST" ? { "content-type": "application/json" } : {}) }, ...(m === "POST" ? { body: "{}" } : {}) });
      const text = await res.text();
      r.freshness = res.status === 402 ? compareFreshness(env.report, acceptsFrom(res.headers, text)) : { comparable: false, note: `live endpoint returned HTTP ${res.status}, not 402` };
      try {
        const wk = await fetch(new URL("/.well-known/x402", env.report.subject.url), { headers: { "user-agent": "coldread-verify/1" } });
        const live = wk.status === 200 ? discoveryAddresses(await wk.text()) : null;
        r.discovery = compareDiscovery(env.report, live, r.freshness.live_pay_tos ?? []);
        if (r.discovery.stale && r.freshness.comparable) { r.freshness.stale = true; r.freshness.why = r.discovery.why; }
      } catch (e) { r.discovery = { comparable: false, note: "well-known fetch failed: " + e.message }; }
    } catch (e) { r.freshness = { comparable: false, note: "live fetch failed: " + e.message }; }
  }
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.valid ? 0 : 1);
}
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("verify.mjs")) main();
