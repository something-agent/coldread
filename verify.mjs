#!/usr/bin/env node
// ColdRead report verifier. No dependencies; Node >= 18.
//   node verify.mjs report.json            verify a saved envelope
//   node verify.mjs https://.../v1/report/<digest>
//   node verify.mjs report.json --online   also compare against the live /.well-known/coldread-keys.json
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

async function main() {
  const [src, flag] = process.argv.slice(2);
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
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.valid ? 0 : 1);
}
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("verify.mjs")) main();
