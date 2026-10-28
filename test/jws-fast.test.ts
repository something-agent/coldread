import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/nist";
import { sha256 } from "@noble/hashes/sha2";
import { verifyJws, verifyJwsFast } from "../src/vendor/proofcheck/jws";

const enc = new TextEncoder();
describe("ColdRead WebCrypto JWS patch", () => {
  it("agrees with the pure-JS verifier for Ed25519 and P-256, valid and tampered", async () => {
    const msg = enc.encode("eyJhbGciOiJFZERTQSJ9.eyJ4IjoxfQ");
    const esk = ed25519.utils.randomPrivateKey();
    const ek = { kind: "ed25519" as const, bytes: ed25519.getPublicKey(esk) };
    const esig = ed25519.sign(msg, esk);
    const psk = p256.utils.randomPrivateKey();
    const pk = { kind: "p256" as const, bytes: p256.getPublicKey(psk, false) };
    const psig = p256.sign(sha256(msg), psk).toCompactRawBytes();
    const cases: [any, any][] = [
      [{ header: { alg: "EdDSA" }, signingInput: msg, signature: esig }, ek],
      [{ header: { alg: "EdDSA" }, signingInput: enc.encode("tampered"), signature: esig }, ek],
      [{ header: { alg: "ES256" }, signingInput: msg, signature: psig }, pk],
      [{ header: { alg: "ES256" }, signingInput: enc.encode("tampered"), signature: psig }, pk],
      [{ header: { alg: "ES256" }, signingInput: msg, signature: esig }, ek],
    ];
    const got = await Promise.all(cases.map(async ([p, k]) => [(await verifyJwsFast(p, k)).ok, verifyJws(p, k).ok]));
    for (const [a, b] of got) expect(a).toBe(b);
    expect(got.map((x) => x[0])).toEqual([true, false, true, false, false]);
  });
});

import "../src/crypto-tune";
import { secp256k1 } from "@noble/curves/secp256k1";
describe("secp256k1 window tuning", () => {
  it("recovers the same signer after the window change", () => {
    const sk = secp256k1.utils.randomPrivateKey(); const h = sha256(enc.encode("offer"));
    const s = secp256k1.sign(h, sk);
    expect(Buffer.from(s.recoverPublicKey(h).toRawBytes(false)).equals(Buffer.from(secp256k1.getPublicKey(sk, false)))).toBe(true);
  });
});
