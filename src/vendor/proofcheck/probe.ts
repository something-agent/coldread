/** Unpaid preflight of an x402 endpoint: fetch the 402, summarise it, and verify any signed offers it carries. */
import { b64Decode, dec } from "./bytes";
import { safeFetch } from "./safe";
import { Ctx, verifyPaymentRequired } from "./verify";

export function parsePaymentRequired(headers: Record<string, string>, body: Uint8Array): { pr: any | null; from: "header" | "body" | null; error?: string } {
  const h = headers["payment-required"];
  if (h) { try { return { pr: JSON.parse(dec.decode(b64Decode(h))), from: "header" }; } catch { /* fall to body */ } }
  try {
    const j = JSON.parse(dec.decode(body));
    if (j && typeof j === "object" && Array.isArray(j.accepts)) return { pr: j, from: "body" };
    return { pr: null, from: null, error: "402 body is JSON but has no accepts[]" };
  } catch { return { pr: null, from: null, error: "could not parse a PaymentRequired object from header or body" }; }
}

export async function probe(url: string, o: { method?: "GET" | "POST"; fetchImpl?: typeof fetch }, ctx: Ctx) {
  const t0 = Date.now();
  const r = await safeFetch(url, { method: o.method ?? "GET", body: o.method === "POST" ? "{}" : undefined, headers: o.method === "POST" ? { "content-type": "application/json" } : undefined, maxBytes: 262_144, fetchImpl: o.fetchImpl ?? ctx.fetchImpl, allowHttp: true });
  const notes: string[] = [];
  const out: any = { url, final_url: r.url, http_status: r.status, redirects: r.redirects, fetch_ms: Date.now() - t0, is_402: r.status === 402 };
  if (r.url.startsWith("http://")) notes.push("endpoint is plain http: payment requirements can be tampered with in transit; serve x402 over https");
  if (r.status !== 402) {
    notes.push(r.status === 405 ? "405: this endpoint may require the other method; retry with method=POST" : `expected HTTP 402 for an unpaid request, got ${r.status}`);
    return { ...out, notes };
  }
  const { pr, from, error } = parsePaymentRequired(r.headers, r.body);
  if (!pr) return { ...out, notes: [...notes, error ?? "unparseable 402"] };
  out.payment_required_from = from;
  out.x402_version = pr.x402Version ?? null;
  out.accepts = (pr.accepts ?? []).map((a: any) => ({ scheme: a.scheme, network: a.network, asset: a.asset, pay_to: a.payTo, amount: a.amount ?? a.maxAmountRequired, max_timeout_seconds: a.maxTimeoutSeconds }));
  out.extensions = Object.keys(pr.extensions ?? {});
  if (!out.accepts.length) notes.push("accepts[] is empty");
  const offers = await verifyPaymentRequired(pr, { resourceUrl: pr?.resource?.url ?? r.url }, ctx);
  out.offer_receipt = offers;
  if (!offers.has_offer_receipt_extension) notes.push("no offer-receipt extension: clients cannot get a signed commitment to these terms (x402 offer-receipt, optional)");
  else if (offers.results.some((x) => x.verdict === "valid_signer_unproven")) notes.push("signed offers verify but the signer is not bound to the domain; publish a did:web document, a _controllers DNS TXT, or an ERC-8004 registration so clients can authorize the key");
  if (!out.extensions.includes("bazaar")) notes.push("no bazaar extension: facilitator discovery catalogs may not list this endpoint");
  return { ...out, notes };
}
