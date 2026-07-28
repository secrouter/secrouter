#!/usr/bin/env bash
# Mint a test JWT from the mock IdP.  Usage: ./get-token.sh [admin|power|basic]
set -euo pipefail
PERSONA="${1:-admin}"
OIDC="${OIDC_URL:-http://localhost:8081}"
curl -fsS "$OIDC/mint?persona=$PERSONA" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
