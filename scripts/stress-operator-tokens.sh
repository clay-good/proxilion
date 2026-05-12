#!/usr/bin/env bash
# Stress test for operator-token auth (ui-less-surfaces.md §4.4).
#
# Toggles the proxy between disabled (default in compose) and enforced
# modes, mints/revokes tokens via proxilion-cli, and asserts the right
# 401/403/200 codes on /api/v1/* endpoints.

set -euo pipefail
trap 'echo "[FAIL] line $LINENO"; exit 1' ERR

PROXY="${PROXY:-https://127.0.0.1:8443}"
CURL="curl -sk --max-time 10"
PG_CONTAINER="${PG_CONTAINER:-proxilion-dev-postgres-1}"
DB_URL="postgres://proxilion:proxilion@127.0.0.1:5432/proxilion"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
step()  { echo; blue "==> $*"; }

pg() { docker exec -i "$PG_CONTAINER" psql -U proxilion -d proxilion -tA -c "$@"; }

step "0. Clean slate"
pg "TRUNCATE operator_tokens;" >/dev/null
green "  ✓ operator_tokens truncated"

step "1. proxilion-cli tokens issue (admin wildcard)"
RESP=$(DATABASE_URL="$DB_URL" cargo run -q -p proxilion-cli -- tokens issue \
        --name "stress-admin" --scope '*' 2>/dev/null)
TOK=$(echo "$RESP" | jq -r '.token')
ID=$(echo "$RESP" | jq -r '.id')
[ -n "$TOK" ] && [[ "$TOK" == pxl_operator_* ]] || { red "✗ no token in response: $RESP"; exit 1; }
green "  ✓ minted admin token id=$ID ($(echo $TOK | head -c 24)…)"

step "2. proxilion-cli tokens issue (ci-bot, narrow scope)"
RESP=$(DATABASE_URL="$DB_URL" cargo run -q -p proxilion-cli -- tokens issue \
        --name "ci-bot" --scope policy:read,actions:read 2>/dev/null)
CI_TOK=$(echo "$RESP" | jq -r '.token')
CI_ID=$(echo "$RESP" | jq -r '.id')
green "  ✓ minted ci-bot token id=$CI_ID"

step "3. tokens list shows both"
N=$(DATABASE_URL="$DB_URL" cargo run -q -p proxilion-cli -- tokens list 2>/dev/null | jq 'length')
[ "$N" = "2" ] || { red "✗ list returned $N, expected 2"; exit 1; }
green "  ✓ tokens list returned $N rows"

step "4. Toggle proxy to ENFORCED operator auth"
PROXILION_DISABLE_OPERATOR_AUTH=0 docker compose up -d proxy >/dev/null 2>&1
sleep 5
docker logs proxilion-dev-proxy-1 2>&1 | tail -50 | grep -q "DISABLE_OPERATOR_AUTH=1" && \
  { red "✗ proxy still reports disabled"; exit 1; } || true
green "  ✓ proxy restarted with operator auth enforced"

step "5. /api/v1/policy without bearer → 401"
CODE=$($CURL -o /dev/null -w '%{http_code}' "$PROXY/api/v1/policy")
[ "$CODE" = "401" ] || { red "✗ expected 401; got $CODE"; exit 1; }
green "  ✓ unauthed /api/v1/policy → 401"

step "6. /api/v1/policy with bogus token → 401"
CODE=$($CURL -H 'Authorization: Bearer pxl_operator_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
        -o /dev/null -w '%{http_code}' "$PROXY/api/v1/policy")
[ "$CODE" = "401" ] || { red "✗ expected 401; got $CODE"; exit 1; }
green "  ✓ bogus token → 401"

step "7. /api/v1/policy with valid admin token → 200"
CODE=$($CURL -H "Authorization: Bearer $TOK" -o /dev/null -w '%{http_code}' "$PROXY/api/v1/policy")
[ "$CODE" = "200" ] || { red "✗ expected 200; got $CODE"; exit 1; }
green "  ✓ admin token → 200"

step "8. /api/v1/policy with ci-bot (policy:read) → 200"
CODE=$($CURL -H "Authorization: Bearer $CI_TOK" -o /dev/null -w '%{http_code}' "$PROXY/api/v1/policy")
[ "$CODE" = "200" ] || { red "✗ expected 200; got $CODE"; exit 1; }
green "  ✓ ci-bot policy:read → 200"

step "9. /api/v1/killswitch/session/{id} with ci-bot → 200 (middleware passes; scope not enforced per-endpoint yet)"
# Per-endpoint scope enforcement is a follow-up; the middleware currently
# requires *any* valid token. Document this and exercise the auth boundary.
CODE=$($CURL -H "Authorization: Bearer $CI_TOK" -X POST \
        -o /dev/null -w '%{http_code}' "$PROXY/api/v1/killswitch/session/00000000-0000-0000-0000-000000000000")
# Killswitch returns 200 even with 0 bearers (just emits a record); the
# point of this test is that the middleware didn't 401/403.
if [ "$CODE" = "200" ] || [ "$CODE" = "400" ]; then
  green "  ✓ ci-bot reached the handler (HTTP $CODE)"
else
  red "✗ expected 200/400 (handler reached); got $CODE"; exit 1
fi

step "10. Revoke ci-bot token"
RESP=$(DATABASE_URL="$DB_URL" cargo run -q -p proxilion-cli -- tokens revoke "$CI_ID" --reason "demo done" 2>/dev/null)
[ "$(echo "$RESP" | jq -r .ok)" = "true" ] || { red "✗ revoke failed: $RESP"; exit 1; }
green "  ✓ ci-bot token revoked"

step "11. ci-bot now returns 401"
CODE=$($CURL -H "Authorization: Bearer $CI_TOK" -o /dev/null -w '%{http_code}' "$PROXY/api/v1/policy")
[ "$CODE" = "401" ] || { red "✗ revoked token should 401; got $CODE"; exit 1; }
green "  ✓ revoked ci-bot → 401"

step "12. Admin token still works"
CODE=$($CURL -H "Authorization: Bearer $TOK" -o /dev/null -w '%{http_code}' "$PROXY/api/v1/policy")
[ "$CODE" = "200" ] || { red "✗ admin token broke; got $CODE"; exit 1; }
green "  ✓ admin token unaffected"

step "13. Metrics tick"
M=$($CURL -H "Authorization: Bearer $TOK" "$PROXY/metrics")
OK=$(echo "$M" | grep -E '^proxilion_operator_auth_total\{result="ok"' | head -1 | awk '{print $NF}')
REJ=$(echo "$M" | grep -E '^proxilion_operator_auth_total\{result="rejected"' | head -1 | awk '{print $NF}')
if [ -n "$OK" ] && [ "$OK" -ge 1 ]; then
  green "  ✓ proxilion_operator_auth_total{result=ok} = $OK"
else
  red "✗ ok metric absent"; exit 1
fi
if [ -n "$REJ" ] && [ "$REJ" -ge 1 ]; then
  green "  ✓ proxilion_operator_auth_total{result=rejected} = $REJ"
else
  red "✗ rejected metric absent"; exit 1
fi

step "14. last_used_at updated"
sleep 1
LU=$(pg "SELECT last_used_at FROM operator_tokens WHERE id='$ID';")
if [ -n "$LU" ]; then
  green "  ✓ last_used_at = $LU"
else
  red "✗ last_used_at not set"; exit 1
fi

step "15. Restore disabled mode (default for compose)"
PROXILION_DISABLE_OPERATOR_AUTH=1 docker compose up -d proxy >/dev/null 2>&1
sleep 5
CODE=$($CURL -o /dev/null -w '%{http_code}' "$PROXY/api/v1/policy")
[ "$CODE" = "200" ] || { red "✗ disabled mode should let unauthed through; got $CODE"; exit 1; }
green "  ✓ disabled-mode unauthed /api/v1/policy → 200"

green ""
green "All operator-token assertions passed."
