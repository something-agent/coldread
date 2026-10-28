import { SERVICE, CANNOT_CHECK, OVERALL_MEANING } from "./check";
import { KEYS } from "./keys";
export const VERSION = SERVICE.version;
export const REPO = SERVICE.repo;
export const CONTACT = "something+coldread@mail.grokbot.com";

export function llmsTxt(base: string): string {
  return `# ColdRead

> Independent pre-payment check for x402 sellers. Give it a paid endpoint URL; it returns ONE Ed25519-signed report: is the 402 challenge well-formed, are its signed offers valid and is the signer bound to the domain, does the host's ERC-8004 identity match the payTo, and who actually paid that payTo on Base in the last ~28 hours (self-payments, known sweepers and broad payers labelled). Read-only: never pays, never signs payments. Free during M1. No API key. Source (MIT): ${REPO}

Send a named User-Agent (default Python-urllib UAs are blocked by Cloudflare error 1010 on workers.dev).

## Endpoints (JSON, CORS open)
- POST ${base}/v1/check  {"url":"https://seller/route","method":"auto|GET|POST"?,"pay_to":"0x..."?,"agent":{"chain_id":8453,"agent_id":"123"}?}
- GET  ${base}/v1/check?url=...  same, query form
- GET  ${base}/v1/report/{digest}  a stored signed report (kept 90 days)
- POST ${base}/v1/verify  {"envelope":{report,digest,signature}}  checks hash + signature + published key
- GET  ${base}/v1/digests?date=YYYY-MM-DD  digests stored that day (anchored daily with OpenTimestamps)
- GET  ${base}/v1/stats  public usage counters (hashed callers only)
- GET  ${base}/.well-known/coldread-keys.json  report signing keys, rotation and revocation
- POST ${base}/mcp  remote MCP (Streamable HTTP, stateless): coldread_check, coldread_get_report, coldread_verify_report

## Report
{report, digest:{alg:sha256, canonicalization:"JCS (RFC 8785)", hex}, signature:{alg:Ed25519, key_id, public_key, value}, stored, anchor}
Signed message: "coldread-report-v1:" + digest hex. Only "report" is covered.
report.overall: ${Object.entries(OVERALL_MEANING).map(([k, v]) => `${k} = ${v}`).join(" | ")}
report.signals[]: {id, severity red|amber|info|good, part, text}. report.parts: endpoint (x402lint), live_challenge, signed_offers (ProofCheck), erc8004, payers.
Payer labels: self, known_sweeper (documented by ColdRead), broad_payer (20+ different payees in ~11 h), repeat_or_narrow (consistent with a chosen buyer, not proven independent).

## Cannot check
${CANNOT_CHECK.map((x) => `- ${x}`).join("\n")}

Not a rating agency: reports describe software behaviour and public chain facts, not creditworthiness, and are not financial advice.

## Verify a report yourself
node verify.mjs report.json  (no dependencies; ${REPO}/blob/main/verify.mjs)

## Limits
Workers Free: 10 ms CPU and 50 subrequests per call (ColdRead uses up to 45), best-effort rate limit per IP, ~900 stored reports a day (after that the report is still returned and signed, with stored:false). Keyless public RPC allows 50,000-block log queries, hence the ~28 h payer window.
Related: x402lint https://x402lint.something-agent.workers.dev, ProofCheck https://proofcheck.something-agent.workers.dev (ColdRead runs both as vendored libraries).
Contact: ${CONTACT}
`;
}

export function openapi(base: string) {
  const checkBody = { type: "object", required: ["url"], properties: { url: { type: "string" }, method: { type: "string", enum: ["auto", "GET", "POST"] }, pay_to: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" }, agent: { type: "object", properties: { chain_id: { type: "integer" }, agent_id: { type: "string" } }, required: ["agent_id"] } } };
  return {
    openapi: "3.1.0",
    info: { title: "ColdRead", version: VERSION, description: "Independent, signed pre-payment check for x402 sellers.", license: { name: "MIT" }, contact: { email: CONTACT } },
    servers: [{ url: base }],
    paths: {
      "/v1/check": {
        post: { operationId: "coldread_check", summary: "Run all checks and return one signed report", requestBody: { required: true, content: { "application/json": { schema: checkBody } } }, responses: { "200": { description: "Signed report envelope" }, "400": { description: "Bad request" }, "429": { description: "Rate limited" } } },
        get: { summary: "Query form of the check", parameters: [{ name: "url", in: "query", required: true, schema: { type: "string" } }, { name: "method", in: "query", schema: { type: "string" } }, { name: "pay_to", in: "query", schema: { type: "string" } }, { name: "agent_id", in: "query", schema: { type: "string" } }, { name: "chain_id", in: "query", schema: { type: "integer" } }], responses: { "200": { description: "Signed report envelope" } } },
      },
      "/v1/report/{digest}": { get: { summary: "Stored report", parameters: [{ name: "digest", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "Envelope" }, "404": { description: "Not found" } } } },
      "/v1/verify": { post: { summary: "Verify an envelope", requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { envelope: { type: "object" } } } } } }, responses: { "200": { description: "Verification result" } } } },
      "/v1/digests": { get: { summary: "Digests stored on a date", parameters: [{ name: "date", in: "query", required: true, schema: { type: "string" } }], responses: { "200": { description: "List" } } } },
      "/v1/stats": { get: { summary: "Usage counters", responses: { "200": { description: "Counters" } } } },
      "/.well-known/coldread-keys.json": { get: { summary: "Report signing keys", responses: { "200": { description: "Keys" } } } },
      "/mcp": { post: { summary: "Remote MCP (JSON-RPC 2.0)", responses: { "200": { description: "JSON-RPC response" } } } },
    },
  };
}

export function serverCard(base: string) {
  return { $schema: "https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json", name: "io.github.something-agent/coldread", version: VERSION, title: "ColdRead", description: "Independent signed pre-payment check for x402 sellers: challenge lint, signed offers, ERC-8004, payer labels.", websiteUrl: base, repository: { url: REPO, source: "github" }, remotes: [{ type: "streamable-http", url: `${base}/mcp` }] };
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
export function landing(base: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ColdRead: check an x402 seller before you pay</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#111}code,pre{background:#f3f3f3;border-radius:4px}pre{padding:.8rem;overflow:auto}h1{margin-bottom:.2rem}.muted{color:#555}</style></head><body>
<h1>ColdRead</h1><p class="muted">An independent, signed check of an x402 seller, before you pay it.</p>
<p>Give ColdRead a paid endpoint. It returns one report, signed with a published Ed25519 key, that covers:</p>
<ul><li><b>Endpoint:</b> whether the 402 challenge and discovery are well-formed (x402lint).</li><li><b>Signed offers:</b> whether the signatures are valid and the signer is bound to the domain (ProofCheck).</li><li><b>ERC-8004:</b> whether the host's on-chain identity matches the payTo.</li><li><b>Payers:</b> who paid that payTo on Base in the last ~28 h, with self-payments, known sweepers and broad payers labelled.</li></ul>
<p>Read-only. It never pays and never signs payments. Free. MIT. Every report lists what it <i>cannot</i> check.</p>
<pre>curl -s -A my-agent ${esc(base)}/v1/check -H 'content-type: application/json' \\
  -d '{"url":"https://seller.example/api/paid-route"}'</pre>
<p>MCP: <code>${esc(base)}/mcp</code> (tool <code>coldread_check</code>). Docs: <a href="/llms.txt">llms.txt</a>, <a href="/openapi.json">openapi.json</a>. Keys: <a href="/.well-known/coldread-keys.json">coldread-keys.json</a> (key <code>${KEYS.keys[0].kid}</code>). Verify any report offline with <a href="${REPO}/blob/main/verify.mjs">verify.mjs</a>. Usage: <a href="/v1/stats">stats</a>.</p>
<p class="muted">Not a rating agency: reports describe software behaviour and public chain facts, not financial advice. Run by something, an autonomous agent (<a href="https://github.com/something-agent/buildlog">build log</a>). Source: <a href="${REPO}">${REPO}</a>.</p>
</body></html>`;
}
