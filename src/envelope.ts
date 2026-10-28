import { canonicalize, sha256Hex } from "./canon";
import { ReportKey, SIG_ALG, SIG_PREFIX, b64u, signingInput, verifySig } from "./sign";

export const CANON = "JCS (RFC 8785)";

/** Wrap a report: digest = sha256(JCS(report)); signature = Ed25519 over "coldread-report-v1:" + digest hex.
 *  Only `report` is covered. `anchor` and `stored` are delivery metadata and are not signed. */
export async function seal(report: unknown, key: ReportKey | null, keysUrl: string) {
  const hex = await sha256Hex(canonicalize(report));
  const signature = key ? { alg: SIG_ALG, key_id: key.kid, public_key: key.publicKey, signed_message: `${SIG_PREFIX}<digest.hex>`, value: b64u(await key.sign(signingInput(hex))), keys_url: keysUrl } : null;
  return { report, digest: { alg: "sha256", canonicalization: CANON, hex }, signature };
}

export async function verifyEnvelope(env: any, pinned?: { kid: string; public_key: string; revoked_at?: string | null }[]) {
  const out: any = { digest_ok: false, signature_ok: false, key_known: null as boolean | null, problems: [] as string[] };
  if (!env || typeof env !== "object" || !env.report) { out.problems.push("not a ColdRead envelope (missing report)"); return out; }
  const hex = await sha256Hex(canonicalize(env.report));
  out.recomputed_digest = hex;
  out.digest_ok = hex === env?.digest?.hex;
  if (!out.digest_ok) out.problems.push("digest does not match the report: the report was changed after signing");
  const s = env.signature;
  if (!s?.value || !s?.public_key) { out.problems.push("unsigned"); return out; }
  out.signature_ok = await verifySig(s.public_key, hex, s.value);
  if (!out.signature_ok) out.problems.push("signature does not verify for the stated public key");
  if (pinned) {
    const k = pinned.find((p) => p.kid === s.key_id && p.public_key === s.public_key);
    out.key_known = !!k;
    if (!k) out.problems.push("key is not in ColdRead's published key list");
    else if (k.revoked_at && String(env.report?.checked_at ?? "") >= k.revoked_at) { out.key_known = false; out.problems.push(`key was revoked at ${k.revoked_at}`); }
  }
  out.valid = out.digest_ok && out.signature_ok && out.key_known !== false;
  return out;
}
