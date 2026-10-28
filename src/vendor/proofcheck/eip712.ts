/**
 * EIP-712 hashing + signer recovery for the two x402 offer-receipt artifacts.
 * The schemas are the normative ones from the extension spec (domain: name "x402 offer" | "x402 receipt", version "1",
 * chainId 1). Implemented directly on @noble (no viem), so the Worker stays small and fast.
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, concat, enc, hexToBytes } from "./bytes";

const k = (s: string) => keccak_256(enc.encode(s));
const u256 = (n: bigint | number): Uint8Array => {
  const v = BigInt(n);
  if (v < 0n || v >= 1n << 256n) throw new Error("uint256 out of range");
  return hexToBytes(v.toString(16).padStart(64, "0"));
};
const str = (s: string) => k(s);

const DOMAIN_TYPE = k("EIP712Domain(string name,string version,uint256 chainId)");
const OFFER_TYPE = k("Offer(uint256 version,string resourceUrl,string scheme,string network,string asset,string payTo,string amount,uint256 validUntil)");
const RECEIPT_TYPE = k("Receipt(uint256 version,string network,string resourceUrl,string payer,uint256 issuedAt,string transaction)");

function domainSeparator(name: string): Uint8Array {
  return keccak_256(concat(DOMAIN_TYPE, str(name), str("1"), u256(1)));
}
const toUint = (v: unknown, field: string): bigint => {
  if (v === undefined || v === null || v === "") return 0n; // spec: unused optional uint fields are 0
  if (typeof v === "number") { if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${field} must be a non-negative integer`); return BigInt(v); }
  if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
  throw new Error(`${field} must be a non-negative integer`);
};
const toStr = (v: unknown, field: string, optional = false): string => {
  if (v === undefined || v === null) { if (optional) return ""; throw new Error(`${field} is required`); }
  if (typeof v !== "string") throw new Error(`${field} must be a string`);
  return v;
};

export interface OfferPayload { version: number; resourceUrl: string; scheme: string; network: string; asset: string; payTo: string; amount: string; validUntil?: number }
export interface ReceiptPayload { version: number; network: string; resourceUrl: string; payer: string; issuedAt: number; transaction?: string }

export function offerDigest(p: OfferPayload): Uint8Array {
  const struct = keccak_256(concat(OFFER_TYPE, u256(toUint(p.version, "version")), str(toStr(p.resourceUrl, "resourceUrl")), str(toStr(p.scheme, "scheme")),
    str(toStr(p.network, "network")), str(toStr(p.asset, "asset")), str(toStr(p.payTo, "payTo")), str(toStr(p.amount, "amount")), u256(toUint(p.validUntil, "validUntil"))));
  return keccak_256(concat(new Uint8Array([0x19, 0x01]), domainSeparator("x402 offer"), struct));
}
export function receiptDigest(p: ReceiptPayload): Uint8Array {
  const struct = keccak_256(concat(RECEIPT_TYPE, u256(toUint(p.version, "version")), str(toStr(p.network, "network")), str(toStr(p.resourceUrl, "resourceUrl")),
    str(toStr(p.payer, "payer")), u256(toUint(p.issuedAt, "issuedAt")), str(toStr(p.transaction, "transaction", true))));
  return keccak_256(concat(new Uint8Array([0x19, 0x01]), domainSeparator("x402 receipt"), struct));
}

export function addressOfPublicKey(uncompressed65: Uint8Array): string {
  return "0x" + bytesToHex(keccak_256(uncompressed65.slice(1)).slice(12));
}
export function toChecksumAddress(addr: string): string {
  const a = addr.toLowerCase().replace(/^0x/, "");
  const h = bytesToHex(keccak_256(enc.encode(a)));
  let out = "0x";
  for (let i = 0; i < a.length; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}

export interface Recovered { signer: string; highS: boolean }
/** Recover the EIP-712 signer from a 65-byte r||s||v hex signature. Throws on malformed signatures. */
export function recoverSigner(digest: Uint8Array, signatureHex: string): Recovered {
  const sig = hexToBytes(signatureHex);
  if (sig.length !== 65) throw new Error("signature must be 65 bytes (r+s+v)");
  let v = sig[64];
  if (v >= 27) v -= 27;
  if (v !== 0 && v !== 1) throw new Error("invalid recovery id");
  const s = secp256k1.Signature.fromCompact(bytesToHex(sig.slice(0, 64))).addRecoveryBit(v);
  const pub = s.recoverPublicKey(digest).toRawBytes(false);
  return { signer: toChecksumAddress(addressOfPublicKey(pub)), highS: s.hasHighS() };
}
