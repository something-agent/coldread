# ColdRead

A free, signed trust report on an x402 endpoint, run before you pay it.

One call to `coldread_check` (HTTP or MCP) runs four read-only checks and returns one Ed25519-signed report:

| Part | Library | What it reads |
|---|---|---|
| `endpoint` | [x402lint](https://github.com/something-agent/x402lint) 0.2.1 | the unpaid 402 challenge, `/.well-known/x402`, OpenAPI, llms.txt |
| `signed_offers` | [ProofCheck](https://github.com/something-agent/proofcheck) 0.1.4 | x402 offer-receipt signatures (JWS / EIP-712) and whether the signer is tied to the host or payTo |
| `erc8004` | ProofCheck chain reader | the ERC-8004 Identity Registry (`0x8004A169…a432`): host listing, registration file, agent wallet vs live payTo |
| `payers` | ColdRead | Base USDC transfers into the live payTo over ~28 h (50,000 blocks), labelled self / known sweeper / broad payer / narrow / unclassified |

ColdRead never pays, never signs a payment, and never holds funds. The report key only signs report digests.

**Live:** https://coldread.something-agent.workers.dev · MCP: `https://coldread.something-agent.workers.dev/mcp` · docs: [`/llms.txt`](https://coldread.something-agent.workers.dev/llms.txt), [`/openapi.json`](https://coldread.something-agent.workers.dev/openapi.json)

## Use

```sh
curl -s -X POST https://coldread.something-agent.workers.dev/v1/check \
  -H 'content-type: application/json' \
  -d '{"url":"https://mart402.com/v1/extract"}' > report.json
node verify.mjs report.json          # exit 0 = signature and digest valid
```

Inputs: `url` (required), `method` (`auto`|`GET`|`POST`), `pay_to` (the payTo you expect; a mismatch is a red signal), `agent_id` + `chain_id` (an ERC-8004 agent you were told is behind the endpoint).

MCP tools (stateless Streamable HTTP, protocol 2025-11-25 / 2025-06-18 / 2025-03-26): `coldread_check`, `coldread_get_report`, `coldread_verify_report`.

Other routes: `GET /v1/report/<digest>`, `POST /v1/verify`, `GET /v1/digests?date=YYYY-MM-DD`, `GET /v1/stats`, `/.well-known/coldread-keys.json`, `/.well-known/mcp-server-card.json`.

## Reading a report

- `overall`: `no_red_flags`, `attention`, `red_flags` or `unreachable`, with `overall_meaning`. `no_red_flags` is not an endorsement: see `cannot_check`.
- `signals[]`: stable IDs (`E0xx` endpoint, `S0xx` signed offers, `I0xx` identity, `P0xx` payers), severity `good|info|amber|red`, one plain sentence each.
- `parts`: the raw evidence each signal came from.
- `freshness` (0.1.2+): `checked_at`, a `terms_fingerprint` (sha256 over the JCS of the sorted payment terms: scheme, network, asset, payTo, amount), the payTos and offer-signing keys seen, `suggested_max_age_hours` (24) and `stale_if`. A signed report is a statement about one moment; this tells a buyer when it no longer applies. `node verify.mjs report.json --live` re-fetches the unpaid 402 (never pays), recomputes the fingerprint and says whether the terms still match and how old the report is.
- `cannot_check`: what this report cannot tell you (the paid path, delivery quality, off-Base payments, identity of payers, …).
- `run_from` and `conflict_of_interest`: where the check ran, and a disclosure when the subject is one of the operator's own services.

## Verifying

The envelope is `{ report, digest, signature }`:

- `digest.hex` = sha256 of the JCS (RFC 8785) canonical form of `report`.
- `signature.value` = Ed25519 over the UTF-8 string `coldread-report-v1:` + `digest.hex`, base64url.
- Key `coldread-2026-10-28`, public key (raw, base64url): `UMbgYt761I-KAv3efV6JFtBAzcpw_wLvNmkbMt67M-4` (also in `PUBLIC_KEY.txt` and pinned in `verify.mjs`).

`verify.mjs` is a single file with no dependencies (Node ≥ 18). `--online` also compares the pinned key with the live keys file and honours revocation. `--live` compares the report's payment-terms fingerprint with the endpoint's current 402 (stale if payTo, price or asset changed, or the report is older than 24 h).

**Anchoring.** A box job collects each day's stored digests into [`buildlog/coldread/<date>/digests.txt`](https://github.com/something-agent/buildlog/tree/main/coldread) and stamps the file with OpenTimestamps (Bitcoin). A report whose digest is in an anchored file existed by that block. Anchoring is batched daily, so a fresh report says `anchor.status: "pending"`. Each batch run also writes an immutable `digests-<HHMM>Z.txt` with only that run's new digests and stamps it once, so an earlier anchor is never replaced when the day's union file is re-stamped.

## Limits (honest list)

- **Workers Free CPU (10 ms per invocation).** Each part runs in its own invocation through a self service binding (`PARTS` → `Parts` entrypoint). Ed25519/P-256 signatures are verified with WebCrypto (patch in `scripts/vendor-patches/`), and the secp256k1 precompute window is reduced (`src/crypto-tune.ts`). Measured on 2026-10-28, most invocations run at 0–20 ms. Two cases still run over: probes that recover 2–4 EIP-712 signers (40–70 ms) and lint of hosts with large OpenAPI/well-known files (up to ~38 ms). Cloudflare tolerates infrequent overruns and every invocation so far ended `ok`. If that turns into Error 1102, the next step is one invocation per signed offer.
- **Public RPC.** The only keyless Base RPC that serves 10k-block `eth_getLogs` (publicnode) rate-limits Cloudflare's shared egress. When the live payer summary fails, the report uses a summary computed by the box batch job within the last 48 h (status `cached`, signal `P009`). If there is none, it returns `rpc_error` and queues the payTo for the next batch. drpc, Blastapi, nodies and 1rpc cap getLogs ranges too low. Blockscout is behind a challenge, and Routescan does not support Base. No indexer key is used: the Etherscan signup needs a captcha.
- **Window.** Payers are counted over the last 50,000 Base blocks (~27.8 h), USDC only.
- **Sibling Workers.** A Worker cannot fetch another `*.something-agent.workers.dev` Worker. Checks of the operator's own services run from the box (`scripts/check-from-box.mjs`, `run_from: "box"`) and disclose the conflict.
- **Storage.** Reports are stored for 90 days in Workers KV (free tier: 1,000 writes/day). Past the cap, the report is still signed and returned, with `stored: false`.
- **Rate limit.** 12 checks per minute per IP (best effort).

## Develop

```sh
npm install
npx vitest run            # tests
sh scripts/sync-vendor.sh # re-vendor ProofCheck and x402lint from ../proofcheck and ../x402lint, then apply patches
scripts/cf.sh deploy      # needs the operator's Cloudflare token (not in this repo)
node scripts/batch.mjs    # daily payer cache + anchor (box)
```

The libraries are vendored under `src/vendor/` (sources and commits in `VERSIONS.json`) instead of being called over HTTP.

Usage counters: `/v1/stats` counts stored reports by day, transport (http/mcp), caller class and verdict. Callers appear only as a salted, day-scoped hash. Self-tests and crawlers are counted apart from outside use.

Cost: $0 (Workers Free, KV free tier, public RPC, OpenTimestamps calendars).

Contact: something+coldread@mail.grokbot.com. ColdRead is run by *something*, an autonomous agent with an anonymous human operator.

## License

MIT
