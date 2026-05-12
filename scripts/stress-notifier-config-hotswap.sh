#!/usr/bin/env bash
# Stress test for DB-stored notifier config + hot swap (ui-less-surfaces.md §8.4).
#
# 1. notifier_config table exists with CHECK constraint
# 2. /api/v1/notifier/config returns null webhook when no env + no DB
# 3. proxilion-cli notifier set-webhook persists row + atomically swaps notifier
# 4. /api/v1/notifier/show now reports configured=true
# 5. /api/v1/notifier/test fires against the new URL (verified via receiver)
# 6. Update the URL via set-webhook → next test hits the NEW URL
# 7. /api/v1/notifier/config GET redacts hmac_key + URL
# 8. Setting disabled=true clears the active notifier
# 9. Bad mode / missing url / missing hmac → 400
# 10. Metric proxilion_notifier_config_changes_total ticks

set -euo pipefail
trap 'echo "[FAIL] line $LINENO"; exit 1' ERR

PROXY="${PROXY:-https://127.0.0.1:8443}"
CURL="curl -sk --max-time 10"
PG_CONTAINER="${PG_CONTAINER:-proxilion-dev-postgres-1}"
RECV_A=proxilion-stress-cfg-a
RECV_B=proxilion-stress-cfg-b

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
step()  { echo; blue "==> $*"; }

pg() { docker exec -i "$PG_CONTAINER" psql -U proxilion -d proxilion -tA -c "$@"; }

step "0. Reset: drop any DB rows + restart with notifier env clear"
pg "TRUNCATE notifier_config;" >/dev/null
docker rm -f "$RECV_A" "$RECV_B" >/dev/null 2>&1 || true
docker restart proxilion-dev-proxy-1 >/dev/null
# Wait for /healthz.
for i in $(seq 1 30); do
  CODE=$($CURL -o /dev/null -w '%{http_code}' "$PROXY/healthz" 2>/dev/null || echo 0)
  [ "$CODE" = "200" ] && break
  sleep 1
done
trap "docker rm -f $RECV_A $RECV_B >/dev/null 2>&1 || true" EXIT

step "1. notifier_config schema check"
PK=$(pg "SELECT column_name FROM information_schema.columns
         WHERE table_name='notifier_config' AND column_name='id';")
[ "$PK" = "id" ] || { red "✗ id column missing"; exit 1; }
CHK=$(pg "SELECT pg_get_constraintdef(oid) FROM pg_constraint
          WHERE conrelid='notifier_config'::regclass AND contype='c';")
echo "$CHK" | grep -q "webhook" || { red "✗ CHECK constraint missing"; exit 1; }
green "  ✓ schema in place"

step "2. /api/v1/notifier/show reports not-configured (no env, no DB)"
SHOW=$($CURL "$PROXY/api/v1/notifier/show")
echo "$SHOW" | jq -e '.webhook.configured == false' >/dev/null \
  || { red "✗ should be not-configured: $SHOW"; exit 1; }
green "  ✓ not configured"

step "3. /api/v1/notifier/config returns webhook: null"
CFG=$($CURL "$PROXY/api/v1/notifier/config")
echo "$CFG" | jq -e '.webhook == null' >/dev/null \
  || { red "✗ should be null: $CFG"; exit 1; }
green "  ✓ webhook:null"

step "4. Stand up receiver A"
docker run -d --rm --name "$RECV_A" --network proxilion-dev_default \
  -e HTTP_PORT=8088 mendhak/http-https-echo:34 >/dev/null
sleep 2

step "5. proxilion-cli notifier set-webhook → A"
RESP=$(cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
       notifier set-webhook \
         --url "http://$RECV_A:8088/blocked-a" \
         --hmac-hex "00112233445566778899aabbccddeeff" 2>/dev/null)
echo "$RESP" | jq -e '.ok == true and .driver == "webhook"' >/dev/null \
  || { red "✗ set-webhook failed: $RESP"; exit 1; }
green "  ✓ set-webhook → ok"

step "6. /api/v1/notifier/show now reports configured=true"
SHOW=$($CURL "$PROXY/api/v1/notifier/show")
echo "$SHOW" | jq -e '.webhook.configured == true' >/dev/null \
  || { red "✗ should be configured: $SHOW"; exit 1; }
green "  ✓ configured (DB row → hot-swapped, no restart)"

step "7. /api/v1/notifier/test fires; receiver A sees one POST"
$CURL -X POST "$PROXY/api/v1/notifier/test" -o /dev/null
sleep 1.5
RX_A=$(docker logs "$RECV_A" 2>&1 | grep -c 'notifier.test' || echo 0)
[ "$RX_A" -ge 1 ] || { red "✗ receiver A missed it (got $RX_A)"; exit 1; }
green "  ✓ receiver A got $RX_A test POST"

step "8. Stand up receiver B + set-webhook → B"
docker run -d --rm --name "$RECV_B" --network proxilion-dev_default \
  -e HTTP_PORT=8088 mendhak/http-https-echo:34 >/dev/null
sleep 2
cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
  notifier set-webhook \
    --url "http://$RECV_B:8088/blocked-b" \
    --hmac-hex "ffeeddccbbaa99887766554433221100" >/dev/null

step "9. Next /api/v1/notifier/test fires at B (NOT A)"
RX_A_BEFORE=$(docker logs "$RECV_A" 2>&1 | grep -c 'notifier.test' || echo 0)
$CURL -X POST "$PROXY/api/v1/notifier/test" -o /dev/null
sleep 1.5
RX_B=$(docker logs "$RECV_B" 2>&1 | grep -c 'notifier.test' || echo 0)
RX_A_AFTER=$(docker logs "$RECV_A" 2>&1 | grep -c 'notifier.test' || echo 0)
[ "$RX_B" -ge 1 ] || { red "✗ receiver B should have got it (got $RX_B)"; exit 1; }
[ "$RX_A_BEFORE" = "$RX_A_AFTER" ] \
  || { red "✗ receiver A wrongly got the new test (before=$RX_A_BEFORE after=$RX_A_AFTER)"; exit 1; }
green "  ✓ hot swap: B got $RX_B, A unchanged at $RX_A_AFTER"

step "10. GET /api/v1/notifier/config redacts hmac_key + URL"
CFG=$($CURL "$PROXY/api/v1/notifier/config")
echo "$CFG" | jq -e '.webhook.config.hmac_key' >/dev/null && {
  red "✗ hmac_key leaked: $CFG"; exit 1
}
echo "$CFG" | jq -e '.webhook.config.hmac_key_set == true' >/dev/null \
  || { red "✗ hmac_key_set missing: $CFG"; exit 1; }
URLR=$(echo "$CFG" | jq -r '.webhook.config.url_redacted')
[ -n "$URLR" ] && [ "$URLR" != "null" ] \
  || { red "✗ url_redacted missing: $CFG"; exit 1; }
green "  ✓ secret redacted ($URLR)"

step "11. Set disabled=true clears the active notifier"
cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
  notifier set-webhook \
    --url "http://$RECV_B:8088/disabled" \
    --hmac-hex "00112233445566778899aabbccddeeff" \
    --disabled >/dev/null
sleep 0.5
SHOW=$($CURL "$PROXY/api/v1/notifier/show")
echo "$SHOW" | jq -e '.webhook.configured == false' >/dev/null \
  || { red "✗ should be disabled: $SHOW"; exit 1; }
green "  ✓ disabled state hot-applied"
# POST /test should now 412
CODE=$($CURL -X POST -o /dev/null -w '%{http_code}' "$PROXY/api/v1/notifier/test")
[ "$CODE" = "412" ] || { red "✗ test should 412 when disabled; got $CODE"; exit 1; }
green "  ✓ /test → 412 when disabled"

step "12. Bad config rejected with 400"
for body in \
  '{"driver":"unknown","config":{}}' \
  '{"driver":"webhook","config":{"hmac_key":"aabbccdd11223344"}}' \
  '{"driver":"webhook","config":{"url":"http://x"}}' \
  '{"driver":"webhook","config":{"url":"http://x","hmac_key":"short"}}'
do
  CODE=$($CURL -X POST -H 'content-type: application/json' \
              -d "$body" -o /dev/null -w '%{http_code}' \
              "$PROXY/api/v1/notifier/config")
  [ "$CODE" = "400" ] || { red "✗ expected 400; got $CODE for $body"; exit 1; }
done
green "  ✓ 4 negative paths → 400"

step "13. Metric ticks"
M=$($CURL "$PROXY/metrics")
N=$(echo "$M" | grep -E '^proxilion_notifier_config_changes_total\{driver="webhook"' | head -1 | awk '{print $NF}')
[ -n "$N" ] && [ "$N" -ge 3 ] || { red "✗ metric not incrementing; got $N"; exit 1; }
green "  ✓ proxilion_notifier_config_changes_total{driver=webhook} = $N (≥3)"

step "14. Restart proxy → DB-stored row survives env-less restart"
# We left the row in disabled state at step 11. Flip enabled=true then
# force a real restart (not just `compose up` — that's a no-op when the
# container's env hasn't changed).
pg "UPDATE notifier_config SET enabled=true WHERE id='webhook';" >/dev/null
docker restart proxilion-dev-proxy-1 >/dev/null
# Wait for healthz to come back.
for i in $(seq 1 30); do
  CODE=$($CURL -o /dev/null -w '%{http_code}' "$PROXY/healthz" 2>/dev/null || echo 0)
  [ "$CODE" = "200" ] && break
  sleep 1
done
SHOW=$($CURL "$PROXY/api/v1/notifier/show")
echo "$SHOW" | jq -e '.webhook.configured == true' >/dev/null \
  || { red "✗ DB row should have survived restart: $SHOW"; exit 1; }
green "  ✓ DB row survives restart (env-less); notifier loaded from notifier_config"

green ""
green "All notifier-config hot-swap assertions passed."
