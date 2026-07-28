#!/usr/bin/env bash
# End-to-end smoke test of the secured test stack.
set -uo pipefail
BASE="${SECROUTER_URL:-http://localhost:18800}"
DIR="$(cd "$(dirname "$0")" && pwd)"
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

echo "1) /health (open):        $(curl -fsS "$BASE/health" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
ADMIN="$("$DIR/get-token.sh" admin)"; BASIC="$("$DIR/get-token.sh" basic)"
echo "   admin token: ${ADMIN:0:24}…"
echo "2) /v1/models no token:   $(code "$BASE/v1/models")  (expect 401)"
echo "3) /v1/models admin:      $(code -H "Authorization: Bearer $ADMIN" "$BASE/v1/models")  (expect 200)"
echo -n "4) chat -> mock model:    "
curl -fsS -X POST "$BASE/v1/chat/completions" -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"hello from the test stack"}]}' \
  | sed -n 's/.*"content":"\(\[mock-llm\][^"]*\).*/\1/p' | head -1
echo "5) /v1/usage (self):      $(curl -fsS -H "Authorization: Bearer $ADMIN" "$BASE/v1/usage" | grep -o '"requestCount": *[0-9]*' | head -1 | grep -o '[0-9]*') request(s) recorded (last 24h)"
echo "6) /admin/api/config:     admin=$(code -H "Authorization: Bearer $ADMIN" "$BASE/admin/api/config")  basic=$(code -H "Authorization: Bearer $BASIC" "$BASE/admin/api/config")  (expect 200 / 403)"
echo "Done. Open the console at $BASE/admin"
