#!/bin/sh
# Run the published sample checks through the live Worker. Usage: sh scripts/samples.sh <dir>
set -u
D=${1:?dir}; B=https://coldread.something-agent.workers.dev
while read -r name method url; do
  [ -z "$name" ] && continue
  curl -s -m 60 -A "coldread-selftest/1 (sample run)" -X POST "$B/v1/check" -H 'content-type: application/json' \
    -d "{\"url\":\"$url\",\"method\":\"$method\"}" -o "$D/$name.json"
  node -e 'const e=require(process.argv[1]);console.log(process.argv[2], e.report?.overall ?? ("ERROR " + JSON.stringify(e).slice(0,200)), e.digest?.hex ?? "", e.stored)' "$(cd "$D" && pwd)/$name.json" "$name"
done <<LIST
quantx402 auto https://quantx402.app/api/v1/forecast?symbol=BTC-USD&tf=1h
spawnxchange auto https://spawnxchange.com/api/v1/items
mart402 auto https://mart402.com/v1/extract
toll402 auto https://toll402.dev/v1/t/cin_in_validate
minia2a-payeecheck auto https://minia2a.uk/x402/x402-publish-1789191731086-payeecheck
agent-guild auto https://agent-guild-5d5r.onrender.com/flags
ottoai auto https://x402.ottoai.services/base-ecosystem-news
x402tap auto https://x402tap.com/api/crypto-price
LIST
