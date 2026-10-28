// Directory-readiness: does this route meet what the main x402 directories check before they list it?
// Each rule records where the requirement comes from and when it was observed. Directories change their
// rules without notice, so "ready" means "passes what they were known to check", not "will be listed".
export type DirStatus = "ready" | "not_ready" | "needs_payment";
export interface DirCheck { ok: boolean | null; text: string }
export interface DirResult { directory: string; status: DirStatus; checks: DirCheck[]; note: string; source: string }

export interface DirInput {
  url: string;
  getStatus?: number | null;      // unpaid GET status (null = not probed / unreachable)
  postStatus?: number | null;     // unpaid POST status
  pr: any | null;                 // parsed PaymentRequired (from whichever method returned 402)
  challengeFrom?: "header" | "body" | null;
  lintErrors: number;             // count of error-level x402lint findings
  openapiText?: string | null;    // body of /openapi.json when it returned 200
  wellKnownText?: string | null;  // body of /.well-known/x402 when it returned 200
}

const EPHEMERAL = /(^|\.)(trycloudflare\.com|ngrok(-free)?\.(app|io|dev)|ngrok\.io|serveo\.net|loca\.lt|localhost\.run|replit\.dev|repl\.co|pinggy\.link|tunnelmole\.net)$/i;

function oapiPathInfo(oapiText: string | null | undefined, url: URL): { parsed: boolean; op: any | null; guidance: boolean } {
  if (!oapiText) return { parsed: false, op: null, guidance: false };
  let d: any;
  try { d = JSON.parse(oapiText); } catch { return { parsed: false, op: null, guidance: false }; }
  const p = d?.paths?.[url.pathname] ?? d?.paths?.[url.pathname.replace(/\/$/, "")];
  const op = p ? (p.post ?? p.get ?? null) : null;
  return { parsed: true, op, guidance: typeof d?.info?.["x-guidance"] === "string" && d.info["x-guidance"].length > 0 };
}

export function directoryReadiness(i: DirInput): DirResult[] {
  const u = new URL(i.url);
  const v2 = i.pr?.x402Version === 2;
  const accepts: any[] = Array.isArray(i.pr?.accepts) ? i.pr.accepts : [];
  const bz = i.pr?.extensions?.bazaar;
  const declared = String(bz?.info?.input?.method ?? "").toUpperCase();
  const desc = String(i.pr?.resource?.description ?? i.pr?.accepts?.[0]?.description ?? "");
  const oa = oapiPathInfo(i.openapiText, u);
  const xpi = oa.op?.["x-payment-info"];
  const xpiOk = !!xpi && Array.isArray(xpi.protocols) && xpi.protocols.some((p: any) => p && typeof p === "object" && "x402" in p);
  const wkListed = !!i.wellKnownText && i.wellKnownText.includes(u.origin + u.pathname);
  const status = (cs: DirCheck[], pay = false): DirStatus => cs.some((c) => c.ok === false) ? "not_ready" : pay ? "needs_payment" : "ready";
  const out: DirResult[] = [];

  const dash: DirCheck[] = [{ ok: i.getStatus === 402, text: `unpaid GET returns 402 (got ${i.getStatus ?? "no response"})` },
    { ok: accepts.length > 0, text: "402 carries a parseable accepts[] list" }];
  out.push({ directory: "x402dash", status: status(dash), checks: dash, source: "observed 2026-10-26: its register endpoint probes the URL with GET and rejects anything that is not a 402",
    note: "If your paid route is POST-only, also answer unpaid GET with the same 402 (never serve or settle on GET)." });

  const scan: DirCheck[] = [{ ok: (i.getStatus === 402 || i.postStatus === 402) && v2 && accepts.length > 0, text: "runtime probe gets a v2 402 with accepts[]" },
    { ok: (oa.parsed && xpiOk) || wkListed, text: "discoverable from the origin: /openapi.json operation with x-payment-info.protocols[{x402}] or the URL listed in /.well-known/x402" },
    { ok: !!bz?.info?.input || !!oa.op?.requestBody || declared === "GET", text: "an input schema is published (bazaar info.input or an OpenAPI requestBody)" },
    { ok: oa.parsed ? oa.guidance : null, text: "OpenAPI info.x-guidance present (recommended, tells agents how to call you)" }];
  out.push({ directory: "x402scan", status: status(scan.filter((c) => c.text.indexOf("recommended") < 0)), checks: scan, source: "x402scan.com/resources/register docs as read 2026-10-21",
    note: "Register at https://x402scan.com/resources/register; it reads /openapi.json first and falls back to /.well-known/x402." });

  const the402: DirCheck[] = [{ ok: v2, text: "x402Version 2 challenge" },
    { ok: i.lintErrors === 0, text: `no error-level x402lint findings (${i.lintErrors})` },
    { ok: i.challengeFrom === "header", text: "challenge in the PAYMENT-REQUIRED header (v2 clients read the header)" }];
  out.push({ directory: "the402", status: status(the402), checks: the402, source: "observed 2026-10-25: listing runs a validator that must return verdict 'payable' for a v2 route",
    note: "A clean x402lint run is a good proxy for its validator, not a guarantee." });

  const bazaar: DirCheck[] = [{ ok: !!bz, text: "extensions.bazaar present in the 402" },
    { ok: bz ? !!bz.info?.input && !!bz.info?.output : false, text: "bazaar info.input and info.output examples present" },
    { ok: bz ? !!bz.schema : false, text: "bazaar JSON schema present" },
    { ok: desc.length > 0 && desc.length <= 500, text: `resource description 1-500 chars (${desc.length})` },
    { ok: !EPHEMERAL.test(u.hostname), text: `host is not a tunnel/preview domain (${u.hostname})` },
    { ok: u.protocol === "https:", text: "https" },
    { ok: declared !== "POST" || i.getStatus === 402 || i.getStatus === 405 ? true : null, text: "GET/HEAD health probes get a 402 or 405 (PayAI hides resources after 3 failed probes in 48 h)" }];
  out.push({ directory: "Bazaar (CDP / PayAI)", status: status(bazaar, true), checks: bazaar, source: "docs.cdp.coinbase.com x402 Bazaar and facilitator.payai.network discovery, as read 2026-10-20",
    note: "Both Bazaars index a resource only after a real payment settles through their facilitator with the bazaar extension echoed. Run `paidpath pay` once (to your own wallet) to trigger it. CDP also needs a CDP facilitator account." });
  return out;
}
