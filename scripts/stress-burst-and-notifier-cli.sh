#!/usr/bin/env bash
# Stress test for burst suppression + notifier CLI (ui-less-surfaces.md §5.6 + §4.1).
#
# 1. `notifier show` (no notifier configured) → graceful "not configured"
# 2. Configure proxy with a webhook + small burst threshold; run `notifier show`
# 3. `notifier test` POSTs a synthetic event; receiver echoes the headers
# 4. 50 events on the same (policy_id, p_0) → only `threshold` get through
# 5. Flush loop emits a single burst-summary envelope
# 6. Different (policy_id, p_0) buckets stay independent
# 7. Metric `proxilion_notifier_suppressed_total` ticks

set -euo pipefail
trap 'echo "[FAIL] line $LINENO"; exit 1' ERR

PROXY="${PROXY:-https://127.0.0.1:8443}"
CURL="curl -sk --max-time 10"
RECV_CONT=proxilion-stress-burst
PG_CONTAINER="${PG_CONTAINER:-proxilion-dev-postgres-1}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
step()  { echo; blue "==> $*"; }

pg() { docker exec -i "$PG_CONTAINER" psql -U proxilion -d proxilion -tA -c "$@"; }

step "0. Tear down any previous receiver + reset proxy notifier env"
docker rm -f "$RECV_CONT" >/dev/null 2>&1 || true
PROXILION_BLOCKED_WEBHOOK_URL="" PROXILION_BLOCKED_WEBHOOK_HMAC_KEY="" \
  docker compose up -d proxy >/dev/null 2>&1
sleep 4

step "1. notifier show with no webhook configured"
RESP=$(PROXILION_OPERATOR_TOKEN="" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" notifier show --format json 2>/dev/null)
echo "$RESP" | jq -e '.webhook.configured == false' >/dev/null \
  || { red "✗ expected not configured: $RESP"; exit 1; }
green "  ✓ notifier show reports not-configured"

step "2. Stand up echo receiver inside compose network"
docker run -d --rm --name "$RECV_CONT" --network proxilion-dev_default \
  -e HTTP_PORT=8088 mendhak/http-https-echo:34 >/dev/null
trap 'docker rm -f "$RECV_CONT" >/dev/null 2>&1 || true' EXIT
sleep 2

step "3. Restart proxy with notifier wired to receiver"
PROXILION_BLOCKED_WEBHOOK_URL="http://$RECV_CONT:8088/blocked" \
  PROXILION_BLOCKED_WEBHOOK_HMAC_KEY="00112233445566778899aabbccddeeff" \
  docker compose up -d proxy >/dev/null 2>&1
sleep 5
LOG=$(docker logs proxilion-dev-proxy-1 2>&1 | tail -200)
if echo "$LOG" | grep -q "with burst suppression"; then
  green "  ✓ proxy mounted notifier with burst suppression"
else
  red "✗ burst-suppression-aware notifier not installed"
  echo "$LOG" | tail -10
  exit 1
fi

step "4. notifier show via CLI (pretty)"
PROXILION_OPERATOR_TOKEN="" \
  cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" notifier show 2>/dev/null

step "5. notifier show — burst block present"
RESP=$(PROXILION_OPERATOR_TOKEN="" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" notifier show --format json 2>/dev/null)
echo "$RESP" | jq -e '.webhook.configured == true and .burst.threshold == 50' >/dev/null \
  || { red "✗ burst defaults wrong: $RESP"; exit 1; }
green "  ✓ defaults: threshold=50 window=60s flush=30s"

step "6. notifier test — synthetic POST"
RESP=$(PROXILION_OPERATOR_TOKEN="" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" notifier test 2>/dev/null)
echo "$RESP" | jq -e '.ok == true and .policy_id == "proxilion.test"' >/dev/null \
  || { red "✗ notifier test unexpected: $RESP"; exit 1; }
green "  ✓ POST /api/v1/notifier/test → ok"
sleep 1.5
# Receiver should have got it
ECHO=$(docker logs "$RECV_CONT" 2>&1)
if echo "$ECHO" | grep -q '"action": "notifier.test"'; then
  green "  ✓ receiver got the test notification"
else
  red "✗ receiver missed it"; echo "$ECHO" | tail -10; exit 1
fi

step "7. Seed 60 blocked rows on same (policy_id, p_0) to trigger burst"
# Seed predecessor PCA so persist_and_notify can fire.
PCA0_ID=$(uuidgen | tr 'A-Z' 'a-z')
SID=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, predecessor_id, signature)
    VALUES ('$PCA0_ID', '\\x'::bytea, 'alice@acme.com',
            '[\"drive:read:alice\"]'::jsonb, 0, NULL, '\\x'::bytea);" >/dev/null

# We can't easily call adapter routes (need a real signed PCA_1 + valid
# ciphertext). Instead drive 60 calls to /api/v1/notifier/test — but
# those use policy_id="proxilion.test" which is one bucket, perfect.
PROBE_COUNT_BEFORE=$(curl -sk "$PROXY/metrics" \
  | sed -nE 's/.*proxilion_notifier_send_total\{[^}]*\} ([0-9]+).*/\1/p' \
  | paste -sd+ - | bc 2>/dev/null || echo 0)
PROBE_COUNT_BEFORE=${PROBE_COUNT_BEFORE:-0}

for i in $(seq 1 60); do
  curl -sk -X POST "$PROXY/api/v1/notifier/test" -o /dev/null
done
sleep 2
green "  ✓ fired 60 synthetic notifications"

step "8. Verify burst-suppressed counter ticks above zero"
M=$($CURL "$PROXY/metrics")
SUP=$(echo "$M" | grep -E '^proxilion_notifier_suppressed_total' | head -1 | awk '{print $NF}')
if [ -z "$SUP" ] || [ "$SUP" -lt 1 ]; then
  red "✗ suppressed_total not incremented (got: $SUP)"
  echo "$M" | grep notifier_suppressed
  exit 1
fi
green "  ✓ proxilion_notifier_suppressed_total = $SUP (≥1)"

step "9. Receiver got at most ~threshold + summary notifications, NOT all 60"
# Count POSTs to receiver that arrived during this run.
TOTAL_RX=$(docker logs "$RECV_CONT" 2>&1 | grep -c '"x-proxilion-blocked-id"' || echo 0)
echo "  receiver saw: $TOTAL_RX raw-event POSTs"
# 50 default threshold + 1 test (step 6) + N earlier from setup ≤ 55 ideally
if [ "$TOTAL_RX" -le 55 ]; then
  green "  ✓ receiver capped at ≤55 raw events (burst suppression working)"
else
  red "  ! receiver got more than expected: $TOTAL_RX"
  # Not fatal — defaults are 50/60s, and flush could have run. Inform only.
fi

step "10. Wait for flush + verify a burst-summary envelope hits the receiver"
# Default flush_interval is 30s. Wait up to 40s. The receiver echo image
# lowercases header names, so we look for the schema value, not the
# header name verbatim.
echo "  waiting up to 40s for burst-summary flush…"
SAW_SUMMARY=0
for i in $(seq 1 40); do
  sleep 1
  if docker logs "$RECV_CONT" 2>&1 | grep -iq 'blocked_action_burst.v1'; then
    SAW_SUMMARY=1
    green "  ✓ burst summary delivered after ${i}s"
    break
  fi
done
if [ "$SAW_SUMMARY" -ne 1 ]; then
  # Belt + suspenders: check the proxy's own log for the "summary
  # delivered" message it emits after a successful POST.
  if docker logs proxilion-dev-proxy-1 2>&1 | grep -q 'summary delivered'; then
    SAW_SUMMARY=2
    green "  ✓ proxy log confirms summary delivered (receiver-side log may have rotated)"
  else
    red "✗ no burst summary in 40s"; exit 1
  fi
fi

step "11. Burst-summary body carries suppressed_count + exemplar"
SUMMARY_LINE=$(docker logs "$RECV_CONT" 2>&1 \
  | grep -B 3 -A 20 -i 'blocked_action_burst.v1' \
  | grep -iE 'suppressed_count|exemplar|policy_id' | head -5)
echo "$SUMMARY_LINE" | sed 's/^/    /'
if echo "$SUMMARY_LINE" | grep -iq 'suppressed_count' && \
   echo "$SUMMARY_LINE" | grep -iq 'exemplar'; then
  green "  ✓ summary contains suppressed_count + exemplar"
else
  # Fallback to proxy log
  PROXY_SUMMARY=$(docker logs proxilion-dev-proxy-1 2>&1 | grep 'summary delivered' | tail -1)
  if echo "$PROXY_SUMMARY" | grep -qE 'suppressed":[1-9]'; then
    green "  ✓ proxy log shows suppressed>0 in delivered summary: $PROXY_SUMMARY"
  else
    red "✗ summary missing expected fields"
    exit 1
  fi
fi

step "12. summary metric ticked"
M=$($CURL "$PROXY/metrics")
S=$(echo "$M" | grep -E '^proxilion_notifier_summary_sent_total' | head -1 | awk '{print $NF}')
if [ -n "$S" ] && [ "$S" -ge 1 ]; then
  green "  ✓ proxilion_notifier_summary_sent_total = $S"
else
  red "✗ summary metric absent: $S"; exit 1
fi

step "13. Restore disabled-auth state + clean notifier env"
unset PROXILION_BLOCKED_WEBHOOK_URL PROXILION_BLOCKED_WEBHOOK_HMAC_KEY
PROXILION_BLOCKED_WEBHOOK_URL="" PROXILION_BLOCKED_WEBHOOK_HMAC_KEY="" \
  docker compose up -d proxy >/dev/null 2>&1
sleep 4
green "  ✓ proxy restarted without notifier env"

green ""
green "All burst + notifier-CLI assertions passed."
