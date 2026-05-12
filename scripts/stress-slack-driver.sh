#!/usr/bin/env bash
# Stress test for Slack interactive driver (ui-less-surfaces.md §5.3).
#
# 1. proxilion-cli notifier set-slack persists row + builds notifier
# 2. /api/v1/notifier/show reports slack: configured=true
# 3. Block Kit JSON shape unit-tested already (notifier::slack::tests)
# 4. Signed-request verify accepts/rejects per Slack v0 spec (unit-tested)
# 5. POST /api/v1/notifier/slack/interact with VALID signature → handler runs
# 6. With missing signature → 401
# 7. With bad signature → 401
# 8. With approved button → blocked_actions row → overridden
# 9. Metric proxilion_slack_interact_total{result=ok} ticks
# 10. /api/v1/notifier/config GET redacts signing_secret + URL

set -euo pipefail
trap 'echo "[FAIL] line $LINENO"; exit 1' ERR

PROXY="${PROXY:-https://127.0.0.1:8443}"
CURL="curl -sk --max-time 10"
PG_CONTAINER="${PG_CONTAINER:-proxilion-dev-postgres-1}"
RECV=proxilion-stress-slack-recv

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
step()  { echo; blue "==> $*"; }

pg() { docker exec -i "$PG_CONTAINER" psql -U proxilion -d proxilion -tA -c "$@"; }

# Compute Slack v0 signature.
slack_sig() {
  local ts="$1" body="$2" secret="$3"
  printf 'v0:%s:%s' "$ts" "$body" | \
    openssl dgst -sha256 -hmac "$secret" -hex | awk '{print "v0=" $NF}'
}

step "0. Clean slate"
pg "TRUNCATE notifier_config;" >/dev/null
docker rm -f "$RECV" >/dev/null 2>&1 || true
docker restart proxilion-dev-proxy-1 >/dev/null
for i in $(seq 1 30); do
  CODE=$($CURL -o /dev/null -w '%{http_code}' "$PROXY/healthz" 2>/dev/null || echo 0)
  [ "$CODE" = "200" ] && break
  sleep 1
done
trap "docker rm -f $RECV >/dev/null 2>&1 || true" EXIT

step "1. Stand up a Slack incoming-webhook stand-in"
docker run -d --rm --name "$RECV" --network proxilion-dev_default \
  -e HTTP_PORT=8088 mendhak/http-https-echo:34 >/dev/null
sleep 2

step "2. proxilion-cli notifier set-slack"
SECRET="8f742231b10e8888abcd99e1b18bf76c"
RESP=$(cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
       notifier set-slack \
         --incoming-webhook-url "http://$RECV:8088/slack-hook" \
         --signing-secret "$SECRET" 2>/dev/null)
echo "$RESP" | jq -e '.ok == true and .driver == "slack"' >/dev/null \
  || { red "✗ set-slack failed: $RESP"; exit 1; }
green "  ✓ slack configured"

step "3. /api/v1/notifier/show reports slack: configured=true"
SHOW=$($CURL "$PROXY/api/v1/notifier/show")
echo "$SHOW" | jq -e '.slack.configured == true' >/dev/null \
  || { red "✗ slack not configured in show: $SHOW"; exit 1; }
green "  ✓ slack configured per /show"

step "4. /api/v1/notifier/config redacts signing_secret + URL"
CFG=$($CURL "$PROXY/api/v1/notifier/config")
echo "$CFG" | jq -e '.slack.config.signing_secret' >/dev/null && {
  red "✗ signing_secret leaked"; exit 1
}
echo "$CFG" | jq -e '.slack.config.signing_secret_set == true' >/dev/null \
  || { red "✗ signing_secret_set missing: $CFG"; exit 1; }
echo "$CFG" | jq -e '.slack.config.incoming_webhook_url_redacted' >/dev/null \
  || { red "✗ url_redacted missing"; exit 1; }
green "  ✓ secret redacted"

step "5. Seed a pending blocked_action + real PCA_0 for the approve to work"
ID_TOKEN=$(curl -fsS -X POST "http://127.0.0.1:9090/default/token" \
  -d grant_type=client_credentials -d client_id=proxilion-dev \
  -d client_secret=dev-secret -d scope=openid | jq -r '.id_token // .access_token')
PCA0=$(curl -fsS -X POST "http://127.0.0.1:8080/v1/pca/issue" \
  -H 'content-type: application/json' \
  -d "$(jq -n --arg c "$ID_TOKEN" '{credential:$c, credential_type:"jwt",
        ops:["drive:read:alice@demo.local"], executor_binding:{service:"stress-slack"}}')")
PCA0_B64=$(jq -r .pca <<<"$PCA0")
PCA0_P0=$(jq -r .p_0 <<<"$PCA0")
PCA0_OPS_JSON=$(jq -c .ops <<<"$PCA0")
PCA0_CBOR_HEX=$(printf %s "$PCA0_B64" | base64 -d | xxd -p | tr -d '\n')
PCA0_ID=$(uuidgen | tr 'A-Z' 'a-z')
SID=$(uuidgen | tr 'A-Z' 'a-z')
BLOCKED_ID=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, predecessor_id, signature, pic_profile)
    VALUES ('$PCA0_ID', '\\x$PCA0_CBOR_HEX'::bytea, '$PCA0_P0',
            '$PCA0_OPS_JSON'::jsonb, 0, NULL, '\\x'::bytea, 'proxilion.v1');" >/dev/null
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$BLOCKED_ID', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'gmail.messages.send', 'POST', '/gmail/v1/users/me/messages/send', 'policy',
            'gmail-external', 'external recipient', '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[], 'pending',
            now() + interval '30 minutes');" >/dev/null
green "  ✓ blocked_id=$BLOCKED_ID"

step "6. POST /api/v1/notifier/slack/interact with VALID signature → handler runs"
TS=$(date +%s)
# Form-encode the JSON payload Slack would send for a button click.
PAYLOAD_JSON=$(jq -nc \
  --arg val "approve:$BLOCKED_ID" \
  --arg user "alice-slack" \
  '{type:"block_actions", user:{username:$user, id:"U001"},
    actions:[{value:$val, action_id:"approve"}]}')
# urlencode the JSON.
PAYLOAD_URLENC=$(jq -rn --arg p "$PAYLOAD_JSON" '$p|@uri')
BODY="payload=$PAYLOAD_URLENC"
SIG=$(slack_sig "$TS" "$BODY" "$SECRET")
RESP=$($CURL -X POST "$PROXY/api/v1/notifier/slack/interact" \
        -H "X-Slack-Signature: $SIG" \
        -H "X-Slack-Request-Timestamp: $TS" \
        -H 'content-type: application/x-www-form-urlencoded' \
        -d "$BODY")
echo "$RESP" | jq -e '.text' >/dev/null \
  || { red "✗ no text in response: $RESP"; exit 1; }
if echo "$RESP" | jq -r '.text' | grep -q "Approved"; then
  green "  ✓ Slack approval succeeded"
else
  red "✗ unexpected response: $RESP"
  exit 1
fi

step "7. blocked_actions row → overridden by Slack"
STATUS=$(pg "SELECT status FROM blocked_actions WHERE id='$BLOCKED_ID';")
APPROVER=$(pg "SELECT approver_subject FROM blocked_actions WHERE id='$BLOCKED_ID';")
[ "$STATUS" = "overridden" ] || { red "✗ status: $STATUS"; exit 1; }
echo "$APPROVER" | grep -q "slack:" || { red "✗ approver: $APPROVER"; exit 1; }
green "  ✓ status=overridden, approver=$APPROVER"

step "8. Missing signature → 401"
CODE=$($CURL -X POST "$PROXY/api/v1/notifier/slack/interact" \
        -H 'content-type: application/x-www-form-urlencoded' \
        -d "$BODY" -o /dev/null -w '%{http_code}')
[ "$CODE" = "401" ] || { red "✗ expected 401 missing sig; got $CODE"; exit 1; }
green "  ✓ unsigned → 401"

step "9. Bad signature → 401"
TS2=$(date +%s)
CODE=$($CURL -X POST "$PROXY/api/v1/notifier/slack/interact" \
        -H "X-Slack-Signature: v0=deadbeef0000000000000000000000000000000000000000000000000000000000" \
        -H "X-Slack-Request-Timestamp: $TS2" \
        -H 'content-type: application/x-www-form-urlencoded' \
        -d "$BODY" -o /dev/null -w '%{http_code}')
[ "$CODE" = "401" ] || { red "✗ expected 401 bad sig; got $CODE"; exit 1; }
green "  ✓ bad sig → 401"

step "10. Old timestamp (10 min ago) → 401"
TS_OLD=$(( $(date +%s) - 600 ))
SIG_OLD=$(slack_sig "$TS_OLD" "$BODY" "$SECRET")
CODE=$($CURL -X POST "$PROXY/api/v1/notifier/slack/interact" \
        -H "X-Slack-Signature: $SIG_OLD" \
        -H "X-Slack-Request-Timestamp: $TS_OLD" \
        -H 'content-type: application/x-www-form-urlencoded' \
        -d "$BODY" -o /dev/null -w '%{http_code}')
[ "$CODE" = "401" ] || { red "✗ expected 401 old ts; got $CODE"; exit 1; }
green "  ✓ stale timestamp → 401"

step "11. Reject path — seed another row + send reject button"
B2=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$B2', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'gmail.messages.send', 'POST', '/gmail/v1/users/me/messages/send', 'policy',
            'gmail-external', 'external', '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[], 'pending',
            now() + interval '30 minutes');" >/dev/null
TS=$(date +%s)
PAYLOAD_JSON=$(jq -nc --arg val "reject:$B2" \
  '{type:"block_actions", user:{username:"on-call", id:"U002"},
    actions:[{value:$val, action_id:"reject"}]}')
PAYLOAD_URLENC=$(jq -rn --arg p "$PAYLOAD_JSON" '$p|@uri')
BODY2="payload=$PAYLOAD_URLENC"
SIG=$(slack_sig "$TS" "$BODY2" "$SECRET")
RESP=$($CURL -X POST "$PROXY/api/v1/notifier/slack/interact" \
        -H "X-Slack-Signature: $SIG" \
        -H "X-Slack-Request-Timestamp: $TS" \
        -H 'content-type: application/x-www-form-urlencoded' \
        -d "$BODY2")
echo "$RESP" | jq -r '.text' | grep -q "Rejected" \
  || { red "✗ reject response unexpected: $RESP"; exit 1; }
STATUS=$(pg "SELECT status FROM blocked_actions WHERE id='$B2';")
[ "$STATUS" = "rejected" ] || { red "✗ status: $STATUS"; exit 1; }
green "  ✓ Slack reject → row=rejected"

step "12. Metrics tick"
M=$($CURL "$PROXY/metrics")
OK=$(echo "$M" | grep -E '^proxilion_slack_interact_total\{[^}]*result="ok"' | head -1 | awk '{print $NF}')
REJ=$(echo "$M" | grep -E '^proxilion_slack_interact_total\{[^}]*result="rejected_signature"' | head -1 | awk '{print $NF}')
[ "${OK:-0}" -ge 2 ] || { red "✗ ok count: $OK"; exit 1; }
[ "${REJ:-0}" -ge 1 ] || { red "✗ rejected count: $REJ"; exit 1; }
green "  ✓ proxilion_slack_interact_total{result=ok}=$OK rejected_signature=$REJ"

green ""
green "All Slack-driver assertions passed."
