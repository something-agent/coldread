#!/bin/sh
# Copy the ProofCheck and x402lint libraries into src/vendor (imported as code, not fetched over workers.dev:
# a Worker cannot reach a sibling workers.dev Worker on the same account). Records the source commits.
set -e
cd "$(dirname "$0")/.."
ROOT=../
rm -rf src/vendor && mkdir -p src/vendor/proofcheck src/vendor/x402lint
for f in auth bytes chain did eip712 jws probe safe util verify; do cp "$ROOT/proofcheck/src/$f.ts" src/vendor/proofcheck/; done
for f in bytes directories known lint safe; do cp "$ROOT/x402lint/src/$f.ts" src/vendor/x402lint/; done
# Identify outbound requests as ColdRead.
sed -i 's#^export const UA = .*#export const UA = "coldread/0.1 (+https://github.com/something-agent/coldread; read-only trust check)";#' src/vendor/proofcheck/safe.ts src/vendor/x402lint/safe.ts
for p in scripts/vendor-patches/*.patch; do patch -s -p1 < "$p"; done  # ColdRead CPU patches (documented in each file)
PC=$(git -C "$ROOT/proofcheck" rev-parse --short HEAD); XL=$(git -C "$ROOT/x402lint" rev-parse --short HEAD)
PV=$(node -p "require('$ROOT/proofcheck/package.json').version"); XV=$(node -p "require('$ROOT/x402lint/package.json').version")
printf '{ "proofcheck": { "version": "%s", "commit": "%s" }, "x402lint": { "version": "%s", "commit": "%s" } }\n' "$PV" "$PC" "$XV" "$XL" > src/vendor/VERSIONS.json
echo "vendored proofcheck $PV ($PC), x402lint $XV ($XL)"
