/** Report signing. The ColdRead report key is a dedicated Ed25519 key: it holds no funds, is not a wallet, and signs
 *  exactly one kind of message: the ASCII string "coldread-report-v1:" followed by the lowercase sha256 hex of the
 *  JCS-canonical report. The fixed prefix means a signature can never be replayed as anything else. */
export const SIG_PREFIX = "coldread-report-v1:";
export const SIG_ALG = "Ed25519";

export const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const unb64u = (s: string) => { const t = s.replace(/-/g, "+").replace(/_/g, "/"); const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4)); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); };
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export interface ReportKey { kid: string; publicKey: string /* raw 32 bytes, base64url */; sign(msg: Uint8Array): Promise<Uint8Array> }

/** Secret format: JSON {"kid", "private_pkcs8_b64", "public_raw_b64url"} (set as a Worker secret, never in the repo). */
export async function loadReportKey(secret: string | undefined): Promise<ReportKey | null> {
  if (!secret) return null;
  const j = JSON.parse(secret);
  const key = await crypto.subtle.importKey("pkcs8", unb64(j.private_pkcs8_b64), { name: "Ed25519" }, false, ["sign"]);
  return { kid: j.kid, publicKey: j.public_raw_b64url, sign: async (m) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, m)) };
}

export const signingInput = (digestHex: string) => new TextEncoder().encode(SIG_PREFIX + digestHex);

export async function verifySig(publicKeyB64u: string, digestHex: string, sigB64u: string): Promise<boolean> {
  try {
    const k = await crypto.subtle.importKey("raw", unb64u(publicKeyB64u), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, k, unb64u(sigB64u), signingInput(digestHex));
  } catch { return false; }
}
