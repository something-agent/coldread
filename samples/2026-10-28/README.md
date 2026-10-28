# Sample reports, 2026-10-28

Real outside x402 endpoints, checked through the live Worker. Each file is a signed envelope: `node ../../verify.mjs <file>`.

| file | endpoint | overall | digest | key signals |
|---|---|---|---|---|
| `agent-guild.json` | https://agent-guild-5d5r.onrender.com/flags | no_red_flags | `d0161f6310fd906a…` | E003, S002, I000, P003 |
| `mart402.json` | https://mart402.com/v1/extract | no_red_flags | `c143c161dba44432…` | E003, S002, I000, P003 |
| `minia2a-payeecheck.json` | https://minia2a.uk/x402/x402-publish-1789191731086-payeecheck | attention | `c3bd5f1ff268e0bb…` | E002, E004, S000, I000, P009, P000 |
| `ottoai.json` | https://x402.ottoai.services/base-ecosystem-news | attention | `19eb1a138645a9b7…` | E003, S003, I000, P003 |
| `quantx402.json` | https://quantx402.app/api/v1/forecast?symbol=BTC-USD&tf=1h | no_red_flags | `84960c1b23d15dfc…` | E003, S000, I000, P009, P000 |
| `spawnxchange.json` | https://spawnxchange.com/api/v1/items | no_red_flags | `bded609c9878bcb4…` | E003, S000, I000, P003 |
| `toll402.json` | https://toll402.dev/v1/t/cin_in_validate | attention | `8d9f86378ae5fa6f…` | E003, S000, I000, P009, P001 |
| `x402tap.json` | https://x402tap.com/api/crypto-price | attention | `359f094d90ab4380…` | E003, S003, I000, P001 |

**Re-run 2026-10-28 ~2:30 PM CDT (ColdRead 0.1.1, x402lint 0.2.3).** The first set of samples (git history) had a bug: x402lint 0.2.1 read
the first 40 hex chars of a signature in ottoai's `ownershipProofs` (and a pool address inside a resource URL elsewhere) as a payTo, and
flagged a false "well-known payTo mismatch" for ottoai. Fixed: only standalone addresses count. minia2a's mismatch is genuine
(the well-known file lists 0xAb62…, the live challenge pays 0x79eb…). The self-check of the operator's own service was dropped from this set.
