#!/usr/bin/env bash
# scripts/stress-step2-3-3-2.sh — exercise the Step 2.3 (blocked queue +
# justified-override) and Step 3.2 (killswitch) APIs end-to-end against the
# running docker stack.
#
# Drives every code path:
#   * GET /api/v1/blocked with each filter
#   * GET /api/v1/blocked/:id (hit + 404)
#   * POST /approve with: missing predecessor, short justification, bad
#     ttl, success, double-approve (Conflict), expired, PIC-refused (ops
#     not a subset)
#   * POST /reject with: empty reason, success, double-reject (Conflict)
#   * POST /killswitch/{session,user,all} including the confirm gate
#   * Concurrent approve/reject races
#   * Concurrent list reads under blocked-write load
#
# Stops the seeder noise by setting NO_DEMO_INTERFERENCE (the demo only
# touches action_events / pca_cache stub rows — we use Trust Plane to mint
# real PCAs for the override path).

set -euo pipefail

PROXY="${PROXY_URL:-https://localhost:8443}"
TP="${TRUST_PLANE_URL:-http://localhost:8080}"
MOCK_OKTA="${MOCK_OKTA_URL:-http://localhost:9090/default}"
PG="docker exec proxilion-dev-postgres-1 psql -U proxilion -d proxilion -At -c"

curl_proxy() { curl -sk -w '\n[%{http_code}]\n' "$@"; }
just() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }

note() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; exit 1; }
pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }

need() { command -v "$1" >/dev/null || { echo missing $1; exit 1; }; }
need jq; need curl; need docker

# ============================================================
note "0. Reset blocked state (keep history, just nuke pending)"
$PG "DELETE FROM blocked_actions WHERE status IN ('pending','overridden','rejected','expired');" >/dev/null
$PG "DELETE FROM kill_records;" >/dev/null
$PG "DELETE FROM agent_bearers;" >/dev/null
$PG "DELETE FROM google_tokens;" >/dev/null
$PG "DELETE FROM oauth_sessions;" >/dev/null
$PG "DELETE FROM pca_cache;" >/dev/null

# ============================================================
note "1. Mint a real PCA_0 via Trust Plane (will be the predecessor)"
ID_TOKEN=$(curl -fsS -X POST "$MOCK_OKTA/token" \
  -d grant_type=client_credentials -d client_id=proxilion-dev \
  -d client_secret=dev-secret -d scope=openid | jq -r '.id_token // .access_token')

PCA0=$(curl -fsS -X POST "$TP/v1/pca/issue" \
  -H 'content-type: application/json' \
  -d "$(jq -n --arg c "$ID_TOKEN" '{
        credential: $c,
        credential_type: "jwt",
        ops: ["drive:read:alice@demo.local","drive:read:engineering"],
        executor_binding: {service:"proxilion-smoke"}}')")
PCA0_B64=$(jq -r '.pca' <<<"$PCA0")
PCA0_P0=$(jq -r '.p_0' <<<"$PCA0")
PCA0_OPS=$(jq -r '.ops | tojson' <<<"$PCA0")
PCA0_CBOR_BYTEA="\\x$(printf %s "$PCA0_B64" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')"

# Seed pca_cache with PCA_0 so override can load it.
PCA0_ID=$(uuidgen | tr 'A-Z' 'a-z')
$PG "INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, predecessor_id, signature) \
     VALUES ('$PCA0_ID', '$PCA0_CBOR_BYTEA'::bytea, '$PCA0_P0', '$PCA0_OPS'::jsonb, 0, NULL, '\\x'::bytea);" >/dev/null
pass "PCA_0 minted, cached as $PCA0_ID"

# Synthetic session_id for the blocked rows.
SESSION_ID=$(uuidgen | tr 'A-Z' 'a-z')

seed_blocked() {
  # $1 status, $2 expires_at sql expr, $3 requested_ops (sql array literal), $4 predecessor
  local status="$1" exp_sql="$2" ops="$3" pred="$4" id
  id=$(uuidgen | tr 'A-Z' 'a-z')
  local pred_sql="NULL"; [ "$pred" != "NULL" ] && pred_sql="'$pred'"
  $PG "INSERT INTO blocked_actions
        (id, request_id, session_id, p_0, vendor, action, method, path, layer, policy_id, detail,
         predecessor_pca_id, requested_ops, status, expires_at)
       VALUES ('$id', gen_random_uuid(), '$SESSION_ID', '$PCA0_P0', 'google',
               'drive.files.get', 'GET', '/drive/v3/files/x', 'policy', 'p1',
               'demo block', $pred_sql, $ops, '$status', $exp_sql);" >/dev/null
  echo "$id"
}

# ============================================================
note "2. List API: empty pending → []"
BODY=$(curl -sk "$PROXY/api/v1/blocked")
[ "$(echo "$BODY" | jq '.rows|length')" = "0" ] || fail "expected empty rows; got $BODY"
pass "empty list"

# ============================================================
note "3. Seed: 1 pending, 1 already-rejected, 1 expired, 1 read_filter (no predecessor)"
PENDING_OK=$(seed_blocked pending "now() + interval '1 hour'" \
  "ARRAY['drive:read:alice@demo.local']::text[]" "$PCA0_ID")
PENDING_AUDIT=$(seed_blocked pending "now() + interval '1 hour'" \
  "ARRAY[]::text[]" "$PCA0_ID")
PENDING_PIC_REFUSE=$(seed_blocked pending "now() + interval '1 hour'" \
  "ARRAY['drive:write:bob/finance/secret.docx']::text[]" "$PCA0_ID")
ALREADY_REJECTED=$(seed_blocked rejected "now() + interval '1 hour'" \
  "ARRAY[]::text[]" "NULL")
ALREADY_EXPIRED=$(seed_blocked pending "now() - interval '1 minute'" \
  "ARRAY['drive:read:alice@demo.local']::text[]" "$PCA0_ID")
NO_PRED=$(seed_blocked pending "now() + interval '1 hour'" \
  "ARRAY[]::text[]" "NULL")
pass "seeded 6 rows"

# ============================================================
note "4. List with filters"
ALL=$(curl -sk "$PROXY/api/v1/blocked?status=all" | jq '.rows|length')
[ "$ALL" -ge 6 ] || fail "status=all should see ≥6; saw $ALL"
PENDING_N=$(curl -sk "$PROXY/api/v1/blocked" | jq '.rows|length')
# Note: list endpoint auto-expires pending rows whose expires_at has passed,
# so ALREADY_EXPIRED becomes 'expired' and only 4 pending remain.
[ "$PENDING_N" = "4" ] || fail "default (pending) filter should see 4; saw $PENDING_N"
P0_N=$(curl -sk "$PROXY/api/v1/blocked?status=all&p_0=$(jq -rn --arg s "$PCA0_P0" '$s|@uri')" | jq '.rows|length')
[ "$P0_N" -ge 6 ] || fail "p_0 filter empty"
EXP_N=$(curl -sk "$PROXY/api/v1/blocked?status=expired" | jq '.rows|length')
[ "$EXP_N" = "1" ] || fail "expected 1 expired (after auto-expiry); saw $EXP_N"
pass "list filters: all=$ALL pending=$PENDING_N p_0=$P0_N expired=$EXP_N"

# ============================================================
note "5. Show: hit + 404"
CODE=$(just "$PROXY/api/v1/blocked/$PENDING_OK")
[ "$CODE" = "200" ] || fail "show should 200; got $CODE"
CODE=$(just "$PROXY/api/v1/blocked/$(uuidgen | tr A-Z a-z)")
[ "$CODE" = "404" ] || fail "show non-existent should 404; got $CODE"
pass "show hit + 404"

# ============================================================
note "6. Approve validation: short justification → 400"
RESP=$(curl -sk -w '\n%{http_code}' -X POST "$PROXY/api/v1/blocked/$PENDING_OK/approve" \
  -H 'content-type: application/json' -d '{"justification":"too short"}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "400" ] || fail "short justification should 400; got $CODE / $RESP"
pass "short justification rejected"

note "6b. Approve validation: ttl_minutes out of range → 400"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$PENDING_OK/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"a valid 20+ character justification for the override","ttl_minutes":9999}')
[ "$CODE" = "400" ] || fail "ttl_minutes 9999 should 400; got $CODE"
pass "ttl_minutes out-of-range rejected"

# ============================================================
note "7. Approve: missing requested_ops → 409"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$PENDING_AUDIT/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"approval with no ops, expecting conflict back from API"}')
[ "$CODE" = "409" ] || fail "approve with empty requested_ops should 409; got $CODE"
pass "empty requested_ops → 409"

note "7b. Approve: no predecessor_pca_id → 409"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$NO_PRED/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"approval with no predecessor PCA id at all in the row"}')
[ "$CODE" = "409" ] || fail "approve with NULL predecessor should 409; got $CODE"
pass "missing predecessor → 409"

# ============================================================
note "8. Approve: PIC refuses (ops not subset of predecessor)"
RESP=$(curl -sk -w '\n%{http_code}' -X POST "$PROXY/api/v1/blocked/$PENDING_PIC_REFUSE/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"trying to override a real monotonicity break for stress test"}')
CODE=$(echo "$RESP" | tail -1)
[ "$CODE" = "422" ] || fail "PIC refuse should 422; got $CODE / $RESP"
pass "PIC-refused override → 422"

# ============================================================
note "9. Approve: happy path"
RESP=$(curl -sk -X POST "$PROXY/api/v1/blocked/$PENDING_OK/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"this is a valid 20+ char justification for stress","approver_subject":"stress@ops.local"}')
OVR_PCA=$(jq -r '.override_pca_id' <<<"$RESP")
HOP=$(jq -r '.hop' <<<"$RESP")
[ "$HOP" = "1" ] || fail "override hop expected 1 (PCA_0→PCA_1); got $HOP"
[ "$OVR_PCA" != "null" ] && [ -n "$OVR_PCA" ] || fail "no override_pca_id in response; got $RESP"
$PG "SELECT status, override_pca_id, approver_subject FROM blocked_actions WHERE id='$PENDING_OK';" \
  | grep -q "overridden|$OVR_PCA|stress@ops.local" || fail "row state not updated"
pass "approved → override PCA $OVR_PCA hop=$HOP"

# Override PCA should be in pca_cache, chained from PCA_0.
CHAIN_PRED=$($PG "SELECT predecessor_id FROM pca_cache WHERE pca_id='$OVR_PCA';")
[ "$CHAIN_PRED" = "$PCA0_ID" ] || fail "override predecessor mismatch: $CHAIN_PRED vs $PCA0_ID"
pass "override PCA chained predecessor=$PCA0_ID"

# ============================================================
note "10. Double-approve → 409"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$PENDING_OK/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"second approve, should be rejected due to overridden status now"}')
[ "$CODE" = "409" ] || fail "double-approve should 409; got $CODE"
pass "double-approve → 409"

# ============================================================
note "11. Approve expired row → 409 + flips to expired"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$ALREADY_EXPIRED/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"approving expired, should detect and 409 it gracefully"}')
# auto-expiry may already have flipped it from prior LIST call, so either
# "block expired before approval" (409) or "blocked row is expired" (409).
[ "$CODE" = "409" ] || fail "approve expired should 409; got $CODE"
STATUS=$($PG "SELECT status FROM blocked_actions WHERE id='$ALREADY_EXPIRED';")
[ "$STATUS" = "expired" ] || fail "expired flip failed: $STATUS"
pass "expired → 409 + status=expired"

# ============================================================
note "12. Reject: validation (empty reason → 400)"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$PENDING_AUDIT/reject" \
  -H 'content-type: application/json' -d '{"reason":""}')
[ "$CODE" = "400" ] || fail "empty reason should 400; got $CODE"
pass "empty reason → 400"

note "12b. Reject: success"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$PENDING_AUDIT/reject" \
  -H 'content-type: application/json' -d '{"reason":"suspicious"}')
[ "$CODE" = "200" ] || fail "reject should 200; got $CODE"
pass "rejected"

note "12c. Double-reject → 409"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$PENDING_AUDIT/reject" \
  -H 'content-type: application/json' -d '{"reason":"again"}')
[ "$CODE" = "409" ] || fail "double-reject should 409; got $CODE"
pass "double-reject → 409"

note "12d. Reject non-existent → 404"
CODE=$(just -X POST "$PROXY/api/v1/blocked/$(uuidgen | tr A-Z a-z)/reject" \
  -H 'content-type: application/json' -d '{"reason":"x"}')
[ "$CODE" = "404" ] || fail "reject 404 should 404; got $CODE"
pass "reject missing → 404"

# ============================================================
note "13. Killswitch: kill_all without confirm → 400"
CODE=$(just -X POST "$PROXY/api/v1/killswitch/all" \
  -H 'content-type: application/json' -d '{"reason":"x"}')
[ "$CODE" = "400" ] || fail "kill all without confirm should 400; got $CODE"
pass "kill all sans confirm → 400"

note "13b. Seed agent_bearers rows (one revoked, two live) and kill by session"
# Create one google_tokens row + oauth_sessions row + bearer for two sessions.
SID1=$(uuidgen | tr A-Z a-z); SID2=$(uuidgen | tr A-Z a-z)
GT1=$(uuidgen | tr A-Z a-z); GT2=$(uuidgen | tr A-Z a-z)
$PG "INSERT INTO oauth_clients (id, name, redirect_uris) VALUES ('claude','Claude',ARRAY['https://x/cb']) ON CONFLICT DO NOTHING;" >/dev/null
$PG "INSERT INTO oauth_sessions
       (id, client_id, agent_redirect_uri, agent_state, agent_code_challenge,
        agent_code_challenge_method, agent_requested_scope, pca_0_id, p_0,
        granted_ops, created_at, expires_at)
     VALUES
       ('$SID1','claude','https://x/cb','st1','chal1','S256','drive.read','$PCA0_ID',
        'alice@demo.local','[\"drive:read:alice\"]'::jsonb, now(), now()+interval '1 hour'),
       ('$SID2','claude','https://x/cb','st2','chal2','S256','drive.read','$PCA0_ID',
        'bob@demo.local','[\"drive:read:bob\"]'::jsonb, now(), now()+interval '1 hour');" >/dev/null
PCA1A=$(uuidgen | tr A-Z a-z); PCA1B=$(uuidgen | tr A-Z a-z)
$PG "INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, predecessor_id, signature) VALUES
       ('$PCA1A','\\x00'::bytea,'alice@demo.local','[]'::jsonb,1,'$PCA0_ID','\\x'::bytea),
       ('$PCA1B','\\x00'::bytea,'bob@demo.local',  '[]'::jsonb,1,'$PCA0_ID','\\x'::bytea);" >/dev/null
$PG "INSERT INTO google_tokens (id, session_id, access_token_ciphertext, access_token_nonce, scope, expires_at) VALUES
       ('$GT1','$SID1','\\x00'::bytea,'\\x00'::bytea,'drive', now()+interval '1 hour'),
       ('$GT2','$SID2','\\x00'::bytea,'\\x00'::bytea,'drive', now()+interval '1 hour');" >/dev/null
$PG "INSERT INTO agent_bearers (bearer_sha256, session_id, pca_1_id, google_tokens_id, scope, created_at) VALUES
       ('\\x01'::bytea,'$SID1','$PCA1A','$GT1','x',now()),
       ('\\x02'::bytea,'$SID2','$PCA1B','$GT2','x',now());" >/dev/null
pass "seeded 2 bearers"

note "13c. Killswitch session $SID1"
RESP=$(curl -sk -X POST "$PROXY/api/v1/killswitch/session/$SID1" \
  -H 'content-type: application/json' -d '{"reason":"stress test session kill","operator_subject":"stress@ops.local"}')
N=$(jq -r '.bearers_revoked' <<<"$RESP")
[ "$N" = "1" ] || fail "session kill should revoke 1; got $N"
pass "session kill revoked $N bearer"

note "13d. Killswitch user bob@demo.local"
RESP=$(curl -sk -X POST "$PROXY/api/v1/killswitch/user/bob@demo.local" \
  -H 'content-type: application/json' -d '{"reason":"stress","operator_subject":"stress@ops.local"}')
N=$(jq -r '.bearers_revoked' <<<"$RESP")
[ "$N" = "1" ] || fail "user kill should revoke 1; got $N"
pass "user kill revoked $N bearer"

note "13e. Killswitch all (no live bearers left → 0)"
RESP=$(curl -sk -X POST "$PROXY/api/v1/killswitch/all" \
  -H 'content-type: application/json' -d '{"confirm":"yes","reason":"sweep"}')
N=$(jq -r '.bearers_revoked' <<<"$RESP")
[ "$N" = "0" ] || fail "kill all should now revoke 0; got $N"
pass "kill all sweep → $N"

KR=$($PG "SELECT count(*) FROM kill_records;")
[ "$KR" = "3" ] || fail "kill_records count expected 3; got $KR"
pass "kill_records audit trail = 3"

# ============================================================
note "14. Concurrency: 20 parallel double-approve attempts; exactly one wins"
WINNER_ID=$(seed_blocked pending "now() + interval '1 hour'" \
  "ARRAY['drive:read:alice@demo.local']::text[]" "$PCA0_ID")
SUCCESS_COUNT=0
TMP=$(mktemp -d)
for i in $(seq 1 20); do
  (curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$PROXY/api/v1/blocked/$WINNER_ID/approve" \
    -H 'content-type: application/json' \
    -d '{"justification":"concurrent race attempt for stress testing approval idempotency"}' > "$TMP/$i") &
done
wait
# Count 200s
SUCCESS_COUNT=$(cat "$TMP"/* | grep -c '^200$' || true)
CONFLICT_COUNT=$(cat "$TMP"/* | grep -c '^409$' || true)
rm -rf "$TMP"
[ "$SUCCESS_COUNT" = "1" ] || fail "expected exactly 1 winner; got $SUCCESS_COUNT (conflicts=$CONFLICT_COUNT)"
pass "race: 1 winner, $CONFLICT_COUNT conflicts"

# ============================================================
note "15. Load: bulk insert 1000 rows + paged list read"
START=$(date +%s)
$PG "INSERT INTO blocked_actions
       (request_id, session_id, p_0, vendor, action, layer, requested_ops, expires_at)
     SELECT gen_random_uuid(), '$SESSION_ID', 'load-test-' || g, 'google',
            'drive.files.get', 'policy', ARRAY[]::text[], now()+interval '1 hour'
       FROM generate_series(1,1000) g;" >/dev/null
INSERT_ELAPSED=$(( $(date +%s) - START ))
CODE=$(just "$PROXY/api/v1/blocked?status=pending&limit=500")
[ "$CODE" = "200" ] || fail "list under 1000-row load failed: $CODE"
TOTAL_ROWS=$($PG "SELECT count(*) FROM blocked_actions WHERE p_0 LIKE 'load-test-%';")
pass "1000-row bulk insert in ${INSERT_ELAPSED}s; list returned 200; rows=$TOTAL_ROWS"

# ============================================================
note "16. Metrics emitted"
METRICS=$(curl -sk "$PROXY/metrics")
echo "$METRICS" | grep -q 'proxilion_overrides_resolved_total' || fail "missing override metric"
echo "$METRICS" | grep -q 'proxilion_killswitch_invocations_total' || fail "missing killswitch metric"
echo "$METRICS" | grep -q 'proxilion_killswitch_revoked_capabilities_total' || fail "missing kill caps metric"
pass "metrics: overrides + killswitch series present"

# ============================================================
printf '\n\033[1;32m=== ALL CHECKS PASSED ===\033[0m\n'
