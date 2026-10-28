/**
 * Signer-authorization evidence. A valid signature only proves *someone* holds the key; the spec (§4.5.1) requires
 * evidence the key is bound to the service. Evidence is graded:
 *   strong - bound to control of the resource's domain, or to the payTo the resource itself returned over TLS
 *   weak   - self-asserted inside the artifact being checked (e.g. offer.payTo == signer, with no independent payTo)
 * Mutable sources (DID docs, DNS) show *current* state only - reported as such.
 */
import { lc } from "./bytes";
import { dnsControllers, didWebUrl, fetchDidWeb, keysFromVerificationMethod, wellKnownRegistration } from "./did";
import { IDENTITY_REGISTRY, loadRegistration, readAgent } from "./chain";
import { PubKey, pubKeyFromJwk, pubKeyFromMultibase } from "./jws";
import { dec, b64urlDecode } from "./bytes";

export interface Signer { evm?: string; pub?: PubKey }
export interface Evidence { method: string; result: "authorized" | "not_found" | "revoked" | "error" | "skipped"; strength?: "strong" | "weak"; detail: string; source?: string }
export interface AuthCtx { fetchImpl?: typeof fetch; network?: boolean }

export function sameKey(candidate: PubKey, s: Signer): boolean {
  if (s.evm && candidate.evmAddress) return lc(s.evm) === lc(candidate.evmAddress);
  if (s.pub && candidate.bytes.length && s.pub.kind === candidate.kind) return s.pub.bytes.length === candidate.bytes.length && s.pub.bytes.every((b, i) => b === candidate.bytes[i]);
  return false;
}

const err = (method: string, e: unknown, source?: string): Evidence => ({ method, result: "error", detail: String((e as Error)?.message ?? e).slice(0, 200), source });

/**
 * A DID key marked `revoked` (W3C security vocabulary, xsd:dateTime) binds only artifacts signed before that time.
 * The artifact's own issuedAt is written by the key holder, so a leaked retired key can backdate it:
 * pre-revocation artifacts get WEAK evidence (needs an independent time: settlement block time, your own receipt log).
 */
export function applyRevocation(e: Evidence, revoked: string | undefined, signedAt?: number): Evidence {
  if (revoked === undefined || e.result !== "authorized") return e;
  const r = Date.parse(revoked);
  if (!Number.isFinite(r)) return { ...e, result: "revoked", strength: undefined, detail: `key is marked revoked ('${revoked.slice(0, 40)}', not a parseable dateTime), so it binds nothing` };
  const rs = Math.floor(r / 1000), iso = new Date(r).toISOString();
  if (signedAt !== undefined && Number.isFinite(signedAt) && signedAt < rs)
    return { ...e, strength: "weak", detail: `${e.detail}; key revoked at ${iso}, and the artifact's issuedAt (${new Date(signedAt * 1000).toISOString()}) is earlier. issuedAt is self-asserted by the key holder (a leaked retired key can backdate), so treat this as binding only with an independent time such as the settlement block time or your own receipt log.` };
  return { ...e, result: "revoked", strength: undefined, detail: `key revoked at ${iso}; ${signedAt !== undefined && Number.isFinite(signedAt) ? `artifact issuedAt ${new Date(signedAt * 1000).toISOString()} is not earlier` : "artifact carries no issuedAt to compare"}, so the key does not bind it` };
}

export function describeSigner(s: Signer): string { return s.evm ?? (s.pub ? `${s.pub.kind}:${s.pub.bytes.length} bytes` : "unknown"); }

export async function gatherEvidence(signer: Signer, host: string, o: { payTo?: string; trustedPayTo?: string[]; agent?: { chainId: number; agentId: string; registry?: string }; skipNetwork?: boolean; signedAt?: number }, ctx: AuthCtx): Promise<Evidence[]> {
  const ev: Evidence[] = [];

  // 1. payTo
  if (signer.evm) {
    if (o.trustedPayTo?.some((p) => lc(p) === lc(signer.evm!))) ev.push({ method: "payTo", result: "authorized", strength: "strong", detail: "signer equals a payTo returned by the resource's own live 402 response (TLS to the resource host). Note: spec recommends a dedicated signing key rather than the payTo key." });
    else if (o.payTo && lc(o.payTo) === lc(signer.evm)) ev.push({ method: "payTo", result: "authorized", strength: "weak", detail: "signer equals the payTo inside the artifact itself - self-asserted; anyone can sign an offer naming their own address. Becomes strong only if payTo is independently confirmed (live 402 or trusted_pay_to)." });
    else ev.push({ method: "payTo", result: "not_found", detail: "signer is not a known payTo for this resource" });
  } else ev.push({ method: "payTo", result: "skipped", detail: "signer is not an EVM key" });

  if (o.skipNetwork) return ev;
  const f = ctx.fetchImpl;

  const tasks: Promise<Evidence[]>[] = [];

  // 2. did:web at the resource host
  tasks.push((async () => {
    const did = `did:web:${host}`;
    try {
      const { doc, url } = await fetchDidWeb(did, f);
      const keys = (doc.verificationMethod ?? []).flatMap(keysFromVerificationMethod);
      const hitKeys = keys.filter((k) => sameKey(k, signer));
      const live = hitKeys.find((k) => k.revoked === undefined);
      const hit = hitKeys.length > 0;
      const e: Evidence = { method: "did_web", result: hit ? "authorized" : "not_found", strength: hit ? "strong" : undefined, detail: hit ? `key listed in ${did} verificationMethod (current state)` : `${keys.length} key(s) in ${did} document, none match the signer`, source: url };
      return [live || !hit ? e : applyRevocation(e, hitKeys[0].revoked, o.signedAt)];
    } catch (e) { return [{ ...err("did_web", e, didSafeUrl(host)), result: /HTTP 404|HTTP 403/.test(String((e as Error).message)) ? "not_found" : "error" } as Evidence]; }
  })());

  // 3. DNS _controllers TXT (DoH)
  tasks.push((async () => {
    try {
      const { controllers, dnssec } = await dnsControllers(host, f);
      if (!controllers.length) return [{ method: "dns_controllers", result: "not_found", detail: `no _controllers.${host} TXT records` } as Evidence];
      let hit = false;
      for (const c of controllers) {
        const m = c.match(/^did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})$/);
        if (m && signer.evm && lc(m[1]) === lc(signer.evm)) hit = true;
        try {
          if (c.startsWith("did:key:")) hit = hit || sameKey(pubKeyFromMultibase(c.slice(8)), signer);
          if (c.startsWith("did:jwk:")) hit = hit || sameKey(pubKeyFromJwk(JSON.parse(dec.decode(b64urlDecode(c.slice(8))))), signer);
        } catch { /* ignore malformed controller */ }
      }
      return [{ method: "dns_controllers", result: hit ? "authorized" : "not_found", strength: hit ? "strong" : undefined, detail: hit ? `signer listed in _controllers.${host} TXT${dnssec ? " (resolver reports DNSSEC-validated)" : " (resolver did NOT report DNSSEC validation)"}` : `${controllers.length} controller(s) published, none match the signer`, source: `dns:_controllers.${host}` } as Evidence];
    } catch (e) { return [err("dns_controllers", e)]; }
  })());

  // 4. ERC-8004 via domain's /.well-known/agent-registration.json, or an explicit agent
  tasks.push((async () => {
    if (!signer.evm) return [{ method: "erc8004", result: "skipped", detail: "signer is not an EVM key" } as Evidence];
    try {
      let refs: { chainId: number; agentId: string; registry: string }[] = [];
      let source: string | undefined;
      if (o.agent) refs = [{ chainId: o.agent.chainId, agentId: o.agent.agentId, registry: o.agent.registry ?? IDENTITY_REGISTRY }];
      else {
        const wk = await wellKnownRegistration(host, f);
        source = `https://${host}/.well-known/agent-registration.json`;
        for (const r of (Array.isArray(wk.registrations) ? wk.registrations : []).slice(0, 2)) {
          const m = String(r?.agentRegistry ?? "").match(/^eip155:(\d+):(0x[0-9a-fA-F]{40})$/);
          if (m && r.agentId !== undefined) refs.push({ chainId: Number(m[1]), agentId: String(r.agentId), registry: m[2] });
        }
        if (!refs.length) return [{ method: "erc8004", result: "not_found", detail: "agent-registration.json present but lists no usable registrations", source } as Evidence];
      }
      const out: Evidence[] = [];
      for (const ref of refs.slice(0, 1)) {
        const a = await readAgent(ref.chainId, ref.agentId, { registry: ref.registry, fetchImpl: f });
        if (!a.owner && !a.agentWallet) { out.push({ method: "erc8004", result: "not_found", detail: `agent ${ref.agentId} on eip155:${ref.chainId} not found (${a.errors[0] ?? "no owner"})`, source }); continue; }
        const walletHit = a.agentWallet && lc(a.agentWallet) === lc(signer.evm);
        const ownerHit = a.owner && lc(a.owner) === lc(signer.evm);
        // Bidirectional check: the on-chain registration file must reference the host (domain verification, per ERC-8004).
        let backlink = "not checked";
        let linked = !!o.agent; // for explicit agent, the caller claimed the link; we report backlink but don't require it
        if (a.agentURI && (walletHit || ownerHit)) {
          try {
            const reg = await loadRegistration(a.agentURI, f);
            const urls = JSON.stringify(reg?.services ?? reg?.endpoints ?? []);
            linked = urls.toLowerCase().includes(host.toLowerCase());
            backlink = linked ? "registration file lists this domain" : "registration file does not list this domain";
          } catch (e) { backlink = `registration file unreadable (${(e as Error).message.slice(0, 60)})`; }
        }
        // A caller-supplied agent id is not domain evidence: anyone can register an ERC-8004 agent whose
        // registration file names any host. Strong only if the domain itself lists that agent.
        let domainNote = "";
        let domainListed = !o.agent;
        if (o.agent && (walletHit || ownerHit)) {
          try {
            const wk = await wellKnownRegistration(host, f);
            const want = `eip155:${ref.chainId}:${ref.registry}`.toLowerCase();
            domainListed = (Array.isArray(wk?.registrations) ? wk.registrations : []).some((r: any) => String(r?.agentId) === String(ref.agentId) && String(r?.agentRegistry ?? "").toLowerCase() === want);
          } catch { domainListed = false; }
          domainNote = domainListed ? "; the domain's /.well-known/agent-registration.json lists this agent" : "; caller-supplied agent: the domain does not list it, and the registration file's host link is self-asserted by whoever registered the agent (weak)";
        }
        const hit = walletHit || ownerHit;
        const strong = hit && (o.agent ? domainListed : linked);
        const weak = !strong && hit && !!o.agent;
        out.push({
          method: "erc8004", result: strong || weak ? "authorized" : "not_found", strength: strong ? "strong" : weak ? "weak" : undefined, source,
          detail: `agent ${ref.agentId} eip155:${ref.chainId}: ${walletHit ? "agentWallet == signer" : ownerHit ? "owner == signer" : `signer is neither agentWallet (${a.agentWallet ?? "unset"}) nor owner (${a.owner ?? "?"})`}; ${backlink}${domainNote}`,
        });
      }
      return out;
    } catch (e) { return [{ ...err("erc8004", e), result: /HTTP 404/.test(String((e as Error).message)) ? "not_found" : "error" } as Evidence]; }
  })());

  for (const r of await Promise.all(tasks)) ev.push(...r);
  return ev;
}
function didSafeUrl(host: string): string { try { return didWebUrl(`did:web:${host}`).url; } catch { return host; } }

export function summarize(ev: Evidence[]): "authorized" | "weak_only" | "unproven" {
  if (ev.some((e) => e.result === "authorized" && e.strength === "strong")) return "authorized";
  if (ev.some((e) => e.result === "authorized")) return "weak_only";
  return "unproven";
}

/**
 * Count of distinct trust roots behind the STRONG evidence (vina, The Colony 2026-10-27).
 * web_host: live payTo, did:web, and a domain-listed ERC-8004 agent all depend on the web server
 * (a hijacker of the web host can register a fresh ERC-8004 agent and list it).
 * dns: _controllers TXT depends on the DNS zone, which can sit at a different provider than the web host.
 * ProofCheck cannot see whether DNS and web share a provider/account, so count is an upper bound on independence.
 */
export interface IndependentRoots { count: number; roots: string[]; note: string }
const ROOT_OF: Record<string, string> = { payTo: "web_host", did_web: "web_host", erc8004: "web_host", dns_controllers: "dns" };
export function independentRoots(ev: Evidence[]): IndependentRoots {
  const roots = [...new Set(ev.filter((e) => e.result === "authorized" && e.strength === "strong").map((e) => ROOT_OF[e.method] ?? e.method))].sort();
  const note = roots.length >= 2
    ? "strong evidence from 2 roots (web host and DNS zone): a web-server compromise alone does not flip both. Upper bound: if one account controls both, they fail together."
    : roots.length === 1
      ? `all strong evidence rests on one root (${roots[0]}); compromise of that root alone can forge it. For high-value use, require a second root (e.g. publish the key in _controllers.<host> TXT at your DNS provider) or a stored earlier snapshot.`
      : "no strong evidence, so no trust root.";
  return { count: roots.length, roots, note };
}
