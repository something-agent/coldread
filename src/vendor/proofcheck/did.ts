/** Key discovery: did:web / did:key / did:jwk, DNS `_controllers` TXT (DoH), /.well-known/agent-registration.json. */
import { b64urlDecode, dec } from "./bytes";
import { addressOfPublicKey, toChecksumAddress } from "./eip712";
import { Jwk, PubKey, pubKeyFromJwk, pubKeyFromMultibase } from "./jws";
import { safeFetch, UA } from "./safe";

export interface DidDoc { id?: string; verificationMethod?: any[]; [k: string]: unknown }

export function didWebUrl(did: string): { url: string; host: string } {
  const m = did.match(/^did:web:([^#?]+)$/);
  if (!m) throw new Error("not a did:web");
  const parts = m[1].split(":").map(decodeURIComponent);
  const host = parts[0];
  if (/[\s/@]/.test(host)) throw new Error("bad did:web host");
  const path = parts.length > 1 ? parts.slice(1).join("/") + "/did.json" : ".well-known/did.json";
  return { url: `https://${host}/${path}`, host: host.toLowerCase() };
}

export function keysFromVerificationMethod(vm: any): PubKey[] {
  const keys: PubKey[] = [];
  const add = (f: () => PubKey) => { try { keys.push(f()); } catch { /* skip unsupported */ } };
  if (vm?.publicKeyJwk) add(() => pubKeyFromJwk(vm.publicKeyJwk as Jwk));
  if (typeof vm?.publicKeyMultibase === "string") add(() => pubKeyFromMultibase(vm.publicKeyMultibase));
  if (typeof vm?.blockchainAccountId === "string") {
    const m = vm.blockchainAccountId.match(/^eip155:\d+:(0x[0-9a-fA-F]{40})$/);
    if (m) keys.push({ kind: "secp256k1", bytes: new Uint8Array(0), evmAddress: toChecksumAddress(m[1]) });
  }
  if (typeof vm?.ethereumAddress === "string" && /^0x[0-9a-fA-F]{40}$/.test(vm.ethereumAddress)) keys.push({ kind: "secp256k1", bytes: new Uint8Array(0), evmAddress: toChecksumAddress(vm.ethereumAddress) });
  // A retired key stays in the document with the W3C security-vocabulary `revoked` dateTime (verticalmarketplace's question).
  if (vm && vm.revoked !== undefined) for (const k of keys) k.revoked = String(vm.revoked);
  return keys;
}

export async function fetchDidWeb(did: string, fetchImpl?: typeof fetch): Promise<{ doc: DidDoc; url: string; host: string }> {
  const { url, host } = didWebUrl(did);
  const r = await safeFetch(url, { fetchImpl, maxBytes: 131_072 });
  if (r.status !== 200) throw new Error(`did.json HTTP ${r.status}`);
  const doc = JSON.parse(dec.decode(r.body)) as DidDoc;
  if (doc.id !== did) throw new Error(`did document id (${String(doc.id)}) does not match ${did}`);
  return { doc, url, host };
}

/** Resolve a JWS kid / DID URL to candidate public keys. did:web resolution performs 1 subrequest. */
export async function resolveKid(kid: string, fetchImpl?: typeof fetch): Promise<{ method: string; domain?: string; keys: PubKey[] }> {
  const base = kid.split("#")[0];
  const frag = kid.includes("#") ? kid.slice(kid.indexOf("#")) : "";
  if (base.startsWith("did:key:")) return { method: "did:key", keys: [pubKeyFromMultibase(base.slice(8))] };
  if (base.startsWith("did:jwk:")) return { method: "did:jwk", keys: [pubKeyFromJwk(JSON.parse(dec.decode(b64urlDecode(base.slice(8)))))] };
  if (base.startsWith("did:pkh:eip155:")) {
    const m = base.match(/^did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})$/);
    if (!m) throw new Error("bad did:pkh");
    return { method: "did:pkh", keys: [{ kind: "secp256k1", bytes: new Uint8Array(0), evmAddress: toChecksumAddress(m[1]) }] };
  }
  if (base.startsWith("did:web:")) {
    const { doc, host } = await fetchDidWeb(base, fetchImpl);
    const vms = (doc.verificationMethod ?? []).filter((vm: any) => !frag || vm.id === kid || vm.id === frag);
    const keys = vms.flatMap(keysFromVerificationMethod);
    if (!keys.length) throw new Error(`no usable verification method matching '${kid}' in did.json`);
    return { method: "did:web", domain: host, keys };
  }
  throw new Error("unsupported kid; expected a did:web, did:key, did:jwk or did:pkh URL");
}

/** `_controllers.<host>` TXT records over DNS-over-HTTPS. Returns controller DIDs, and whether the resolver validated DNSSEC (AD flag). */
export async function dnsControllers(host: string, fetchImpl?: typeof fetch): Promise<{ controllers: string[]; dnssec: boolean }> {
  const name = `_controllers.${host}`;
  const f = fetchImpl ?? fetch;
  const r = await f(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`, { headers: { accept: "application/dns-json", "user-agent": UA }, signal: AbortSignal.timeout(6000) });
  if (!r.ok) throw new Error(`DoH HTTP ${r.status}`);
  const j = await r.json() as any;
  const out: string[] = [];
  for (const a of j.Answer ?? []) {
    if (a.type !== 16 || typeof a.data !== "string") continue;
    const txt = a.data.replace(/"\s*"/g, "").replace(/^"|"$/g, "");
    for (const tok of txt.split(/[\s,;]+/)) if (/^did:[a-z0-9]+:/i.test(tok)) out.push(tok);
  }
  return { controllers: out, dnssec: j.AD === true };
}

export async function wellKnownRegistration(host: string, fetchImpl?: typeof fetch): Promise<any> {
  const r = await safeFetch(`https://${host}/.well-known/agent-registration.json`, { fetchImpl, maxBytes: 262_144 });
  if (r.status !== 200) throw new Error(`agent-registration.json HTTP ${r.status}`);
  return JSON.parse(dec.decode(r.body));
}
export { addressOfPublicKey };
