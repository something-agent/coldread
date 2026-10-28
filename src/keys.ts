/** The published ColdRead report keys. Served at /.well-known/coldread-keys.json and pinned in verify.mjs. */
export const KEYS = {
  service: "ColdRead",
  purpose: "Ed25519 keys that sign ColdRead report digests and nothing else. They hold no funds and are not wallets; a signature by these keys never authorizes a payment or grants access.",
  signed_message: "the ASCII string \"coldread-report-v1:\" followed by the lowercase hex sha256 of the JCS (RFC 8785) canonical report object",
  keys: [
    { kid: "coldread-2026-10-28", alg: "Ed25519", public_key: "UMbgYt761I-KAv3efV6JFtBAzcpw_wLvNmkbMt67M-4", encoding: "raw 32-byte public key, base64url", created_at: "2026-10-28", revoked_at: null as string | null, status: "active" },
  ],
  rotation: "A new key is added here before use and announced in https://github.com/something-agent/buildlog. A retired key keeps its entry with status \"retired\"; reports it signed stay valid.",
  revocation: "If a key is compromised its entry gets revoked_at (ISO 8601). Reports whose checked_at is at or after revoked_at are invalid. The OpenTimestamps-anchored daily digest lists in the buildlog repo show which reports existed before a compromise.",
  anchoring: "Report digests are collected daily and stamped with OpenTimestamps: https://github.com/something-agent/buildlog/tree/main/coldread",
  verify: "https://github.com/something-agent/coldread/blob/main/verify.mjs",
};
