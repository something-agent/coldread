/** JWS compact verification for the algorithms the offer-receipt extension names: ES256K, EdDSA (Ed25519), ES256. */
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/nist";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { addressOfPublicKey, toChecksumAddress } from "./eip712";
import { b64urlDecode, base58Decode, concat, dec, enc } from "./bytes";

export interface Jwk { kty: string; crv?: string; x?: string; y?: string; [k: string]: unknown }
export interface ParsedJws { header: Record<string, any>; payload: any; signingInput: Uint8Array; signature: Uint8Array; payloadRaw: string }

export function parseJws(compact: string): ParsedJws {
  if (typeof compact !== "string") throw new Error("JWS must be a string");
  const parts = compact.split(".");
  if (parts.length !== 3) throw new Error("JWS compact serialization needs 3 dot-separated parts");
  const header = JSON.parse(dec.decode(b64urlDecode(parts[0])));
  const payloadRaw = dec.decode(b64urlDecode(parts[1]));
  return { header, payload: JSON.parse(payloadRaw), payloadRaw, signingInput: enc.encode(`${parts[0]}.${parts[1]}`), signature: b64urlDecode(parts[2]) };
}

export type KeyKind = "secp256k1" | "ed25519" | "p256";
export interface PubKey { kind: KeyKind; bytes: Uint8Array /* secp256k1/p256: uncompressed 65B; ed25519: 32B */; evmAddress?: string; /** W3C security-vocab `revoked` dateTime from the DID document, if any */ revoked?: string }

export function pubKeyFromJwk(jwk: Jwk): PubKey {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string") {
    const x = b64urlDecode(jwk.x);
    if (x.length !== 32) throw new Error("bad Ed25519 key length");
    return { kind: "ed25519", bytes: x };
  }
  if (jwk.kty === "EC" && typeof jwk.x === "string" && typeof jwk.y === "string") {
    const pt = concat(new Uint8Array([4]), b64urlDecode(jwk.x), b64urlDecode(jwk.y));
    if (pt.length !== 65) throw new Error("bad EC key length");
    if (jwk.crv === "secp256k1") { secp256k1.ProjectivePoint.fromHex(pt); return { kind: "secp256k1", bytes: pt, evmAddress: toChecksumAddress(addressOfPublicKey(pt)) }; }
    if (jwk.crv === "P-256") { p256.ProjectivePoint.fromHex(pt); return { kind: "p256", bytes: pt }; }
  }
  throw new Error(`unsupported JWK (kty=${jwk.kty}, crv=${jwk.crv})`);
}

function readVarint(b: Uint8Array): { code: number; rest: Uint8Array } {
  let code = 0, shift = 0, i = 0;
  for (; i < b.length; i++) { code |= (b[i] & 0x7f) << shift; if (!(b[i] & 0x80)) { i++; break; } shift += 7; }
  return { code, rest: b.slice(i) };
}
/** did:key (base58btc multibase 'z'): Ed25519 (0xed), secp256k1 (0xe7), P-256 (0x1200). */
export function pubKeyFromMultibase(mb: string): PubKey {
  if (!mb.startsWith("z")) throw new Error("only base58btc multibase ('z') is supported");
  const { code, rest } = readVarint(base58Decode(mb.slice(1)));
  if (code === 0xed && rest.length === 32) return { kind: "ed25519", bytes: rest };
  if (code === 0xe7) { const pt = secp256k1.ProjectivePoint.fromHex(rest).toRawBytes(false); return { kind: "secp256k1", bytes: pt, evmAddress: toChecksumAddress(addressOfPublicKey(pt)) }; }
  if (code === 0x1200) return { kind: "p256", bytes: p256.ProjectivePoint.fromHex(rest).toRawBytes(false) };
  throw new Error(`unsupported multicodec 0x${code.toString(16)}`);
}

const ALG_KIND: Record<string, KeyKind> = { ES256K: "secp256k1", EdDSA: "ed25519", ES256: "p256" };

export function verifyJws(p: ParsedJws, key: PubKey): { ok: boolean; reason?: string } {
  const alg = String(p.header.alg);
  const want = ALG_KIND[alg];
  if (!want) return { ok: false, reason: `unsupported alg '${alg}' (supported: ES256K, EdDSA, ES256)` };
  if (want !== key.kind) return { ok: false, reason: `alg ${alg} does not match key type ${key.kind}` };
  try {
    if (key.kind === "ed25519") return { ok: p.signature.length === 64 && ed25519.verify(p.signature, p.signingInput, key.bytes) };
    if (p.signature.length !== 64) return { ok: false, reason: "ECDSA JWS signature must be 64 bytes (r||s)" };
    const digest = sha256(p.signingInput);
    const curve = key.kind === "secp256k1" ? secp256k1 : p256;
    return { ok: curve.verify(p.signature, digest, key.bytes, { lowS: false }) };
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
}

/** ColdRead patch: verify Ed25519 and P-256 with WebCrypto (native; the pure-JS path costs tens of ms of
 *  Worker CPU). Falls back to verifyJws when WebCrypto refuses the key or algorithm. Same verdicts. */
export async function verifyJwsFast(p: ParsedJws, key: PubKey): Promise<{ ok: boolean; reason?: string }> {
  const want = ALG_KIND[String(p.header.alg)];
  const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;
  if (!subtle || want !== key.kind || p.signature.length !== 64) return verifyJws(p, key);
  try {
    if (key.kind === "ed25519" && key.bytes.length === 32) {
      const k = await subtle.importKey("raw", key.bytes, { name: "Ed25519" }, false, ["verify"]);
      return { ok: await subtle.verify({ name: "Ed25519" }, k, p.signature, p.signingInput) };
    }
    if (key.kind === "p256" && key.bytes.length === 65 && key.bytes[0] === 4) {
      const k = await subtle.importKey("raw", key.bytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      return { ok: await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, p.signature, p.signingInput) };
    }
  } catch { /* fall through */ }
  return verifyJws(p, key);
}
