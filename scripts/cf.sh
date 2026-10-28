#!/bin/sh
# Run wrangler with the account token read from secrets/ (never echoed).
cd "$(dirname "$0")/.."
CLOUDFLARE_API_TOKEN="$(cat ../secrets/cloudflare-token.txt)" CLOUDFLARE_ACCOUNT_ID=e69789e19bc46a76e0f5f34e51585e49 exec npx wrangler "$@"
