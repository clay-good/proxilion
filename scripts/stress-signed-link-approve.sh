#!/usr/bin/env bash
# Stress test for signed-URL approve/reject (ui-less-surfaces.md §5.4).
#
# 1. Seed a real blocked_action with a Trust-Plane-minted PCA_0
# 2. Issue an approve link (operator-authed)
# 3. GET the landing page (unauthenticated — token IS the credential)
# 4. POST short justification → validation error
# 5. POST valid justification → success page, blocked row marked overridden
# 6. Re-use the same token → "already used"
# 7. Expired token → "expired"
# 8. Reject path: issue + use a reject link, blocked row → rejected
# 9. HTML escaping of detail field with payload
# 10. Bad token UUID → 400/error page

set -euo pipefail
trap 'echo "[FAIL] line $LINENO"; exit 1' ERR

PROXY="${PROXY:-https://127.0.0.1:8443}"
CURL="curl -sk --max-time 10"
PG_CONTAINER="${PG_CONTAINER:-proxilion-dev-postgres-1}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
step()  { echo; blue "==> $*"; }

pg() { docker exec -i "$PG_CONTAINER" psql -U proxilion -d proxilion -tA -c "$@"; }

step "0. Mint real PCA_0 + seed a pending blocked_action"
ID_TOKEN=$(curl -fsS -X POST "http://127.0.0.1:9090/default/token" \
  -d grant_type=client_credentials -d client_id=proxilion-dev \
  -d client_secret=dev-secret -d scope=openid | jq -r '.id_token // .access_token')
PCA0=$(curl -fsS -X POST "http://127.0.0.1:8080/v1/pca/issue" \
  -H 'content-type: application/json' \
  -d "$(jq -n --arg c "$ID_TOKEN" '{credential:$c, credential_type:"jwt",
        ops:["drive:read:alice@demo.local"], executor_binding:{service:"stress-signed-link"}}')")
PCA0_B64=$(jq -r .pca <<<"$PCA0")
PCA0_P0=$(jq -r .p_0 <<<"$PCA0")
PCA0_OPS_JSON=$(jq -c .ops <<<"$PCA0")
PCA0_CBOR_HEX=$(printf %s "$PCA0_B64" | base64 -d | xxd -p | tr -d '\n')
PCA0_ID=$(uuidgen | tr 'A-Z' 'a-z')
SID=$(uuidgen | tr 'A-Z' 'a-z')
BLOCKED_ID=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, predecessor_id, signature)
    VALUES ('$PCA0_ID', '\\x$PCA0_CBOR_HEX'::bytea, '$PCA0_P0',
            '$PCA0_OPS_JSON'::jsonb, 0, NULL, '\\x'::bytea);" >/dev/null
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$BLOCKED_ID', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'drive.files.get', 'GET', '/drive/v3/files/abc', 'policy',
            'demo-policy', '<script>alert(1)</script> escaping test', '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[], 'pending',
            now() + interval '30 minutes');" >/dev/null
green "  ✓ seeded blocked_id=$BLOCKED_ID"

step "1. Issue an approve link (operator API)"
RESP=$($CURL -X POST "$PROXY/api/v1/blocked/$BLOCKED_ID/issue-link" \
       -H 'content-type: application/json' \
       -d '{"action":"approve","ttl_minutes":30,"approver_hint":"on-call@acme.com"}')
TOKEN=$(echo "$RESP" | jq -r .token_id)
URL=$(echo "$RESP" | jq -r .url)
echo "  link: $URL"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { red "✗ no token in response: $RESP"; exit 1; }
green "  ✓ minted approve link token=$TOKEN"

step "2. GET /notifier/approve?t=... — landing page (unauthenticated)"
HTML=$($CURL "$PROXY/notifier/approve?t=$TOKEN")
echo "$HTML" | grep -q "Approve blocked action" || \
  { red "✗ landing page missing heading"; echo "$HTML" | head -20; exit 1; }
echo "$HTML" | grep -q "$PCA0_P0" || \
  { red "✗ p_0 missing from landing"; exit 1; }
green "  ✓ landing page renders, carries p_0"

step "3. HTML escaping: <script> in detail field is escaped"
if echo "$HTML" | grep -q '&lt;script&gt;'; then
  green "  ✓ detail field XSS-escaped"
else
  red "✗ HTML escaping failed"
  echo "$HTML" | grep -i 'script' | head -3
  exit 1
fi
echo "$HTML" | grep -q '<script>alert(1)</script>' && { red "✗ unescaped <script> in body"; exit 1; } || true

step "4. POST short justification → validation error page"
RESP=$($CURL -X POST "$PROXY/notifier/approve" \
       -d "t=$TOKEN&justification=short")
if echo "$RESP" | grep -q "at least 20 characters"; then
  green "  ✓ short justification rejected"
else
  red "✗ short justification didn't surface error"; echo "$RESP" | head -10; exit 1
fi

step "5. Verify token NOT consumed by failed submit (still pending)"
CONSUMED=$(pg "SELECT consumed_at FROM notifier_tokens WHERE token_id='$TOKEN';")
if [ -z "$CONSUMED" ]; then
  green "  ✓ token still unconsumed after validation error"
else
  red "✗ token wrongly consumed: $CONSUMED"; exit 1
fi

step "6. POST valid justification → success + token consumed"
RESP=$($CURL -X POST "$PROXY/notifier/approve" \
       -d "t=$TOKEN&justification=approving via signed link to verify end-to-end behaves")
if echo "$RESP" | grep -q "Action approved"; then
  green "  ✓ success banner rendered"
else
  red "✗ no success banner"; echo "$RESP" | head -20; exit 1
fi
if echo "$RESP" | grep -qE "Override PCA [0-9a-f-]+ minted at hop"; then
  green "  ✓ success page carries override PCA id + hop"
else
  red "✗ override info missing"; exit 1
fi

step "7. Blocked row is now 'overridden'"
STATUS=$(pg "SELECT status FROM blocked_actions WHERE id='$BLOCKED_ID';")
[ "$STATUS" = "overridden" ] || { red "✗ status not overridden: $STATUS"; exit 1; }
APPROVER=$(pg "SELECT approver_subject FROM blocked_actions WHERE id='$BLOCKED_ID';")
[ "$APPROVER" = "on-call@acme.com" ] || { red "✗ approver wrong: $APPROVER"; exit 1; }
green "  ✓ status=overridden, approver=$APPROVER"

step "8. Re-using the same token → 'already used'"
RESP=$($CURL "$PROXY/notifier/approve?t=$TOKEN")
if echo "$RESP" | grep -qiE "already used|Link unknown or already used"; then
  green "  ✓ replay attempt blocked"
else
  red "✗ replay not blocked"; echo "$RESP" | head -10; exit 1
fi

step "9. Reject path: seed another row + issue+use a reject link"
B2=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$B2', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'drive.files.get', 'GET', '/drive/v3/files/xyz', 'policy',
            'demo-policy', 'cli-stress', '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[], 'pending',
            now() + interval '30 minutes');" >/dev/null
RESP=$($CURL -X POST "$PROXY/api/v1/blocked/$B2/issue-link" \
       -H 'content-type: application/json' \
       -d '{"action":"reject"}')
T2=$(echo "$RESP" | jq -r .token_id)
RESP=$($CURL -X POST "$PROXY/notifier/approve" \
       -d "t=$T2&reason=stress-test rejection via signed link")
if echo "$RESP" | grep -q "Action rejected"; then
  green "  ✓ reject success banner"
else
  red "✗ reject failed: $RESP" | head -10; exit 1
fi
STATUS=$(pg "SELECT status FROM blocked_actions WHERE id='$B2';")
[ "$STATUS" = "rejected" ] || { red "✗ status not rejected: $STATUS"; exit 1; }
green "  ✓ blocked row=rejected"

step "10. Issue-link for already-resolved row → 409"
CODE=$($CURL -X POST "$PROXY/api/v1/blocked/$BLOCKED_ID/issue-link" \
       -H 'content-type: application/json' \
       -d '{"action":"approve"}' -o /dev/null -w '%{http_code}')
[ "$CODE" = "409" ] || { red "✗ expected 409; got $CODE"; exit 1; }
green "  ✓ resolved row → 409"

step "11. Issue-link with invalid action → 400"
B3=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$B3', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'drive.files.get', 'GET', '/drive/v3/files/xxx', 'policy',
            'demo-policy', 'stress', '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[], 'pending',
            now() + interval '30 minutes');" >/dev/null
CODE=$($CURL -X POST "$PROXY/api/v1/blocked/$B3/issue-link" \
       -H 'content-type: application/json' \
       -d '{"action":"delete"}' -o /dev/null -w '%{http_code}')
[ "$CODE" = "400" ] || { red "✗ expected 400; got $CODE"; exit 1; }
green "  ✓ bad action → 400"

step "12. Bad token UUID in landing → graceful error page"
RESP=$($CURL "$PROXY/notifier/approve?t=00000000-0000-0000-0000-000000000000")
if echo "$RESP" | grep -qE "Link unknown|Error"; then
  green "  ✓ unknown UUID → friendly error page"
else
  red "✗ unknown token didn't error gracefully"; exit 1
fi

step "13. Expired token → graceful error"
B4=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$B4', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'drive.files.get', 'GET', '/drive/v3/files/expired', 'policy',
            'demo-policy', 'stress', '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[], 'pending',
            now() + interval '30 minutes');" >/dev/null
RESP=$($CURL -X POST "$PROXY/api/v1/blocked/$B4/issue-link" \
       -H 'content-type: application/json' \
       -d '{"action":"approve","ttl_minutes":1}')
T4=$(echo "$RESP" | jq -r .token_id)
# Force expiry in DB.
pg "UPDATE notifier_tokens SET expires_at = now() - interval '1 minute' WHERE token_id='$T4';" >/dev/null
RESP=$($CURL "$PROXY/notifier/approve?t=$T4")
if echo "$RESP" | grep -qi "expired"; then
  green "  ✓ expired token surfaced"
else
  red "✗ expiry not handled"; echo "$RESP" | head -10; exit 1
fi

step "14. Metrics tick on email channel"
M=$($CURL "$PROXY/metrics")
E=$(echo "$M" | grep -E '^proxilion_overrides_resolved_total\{[^}]*channel="email"' | head -1 | awk '{print $NF}')
if [ -n "$E" ] && [ "$E" -ge 1 ]; then
  green "  ✓ proxilion_overrides_resolved_total{channel=email} = $E"
else
  red "✗ email channel metric absent"
  echo "$M" | grep overrides_resolved | head
  exit 1
fi
REQ=$(echo "$M" | grep -E '^proxilion_overrides_requested_total\{channel="email_link"' | head -1 | awk '{print $NF}')
# Three successful issue-link calls in this run: step 1 (approve), step 9
# (reject), step 13 (expired-test). All three increment the counter, so
# we expect exactly 3.
if [ -n "$REQ" ] && [ "$REQ" -ge 3 ]; then
  green "  ✓ proxilion_overrides_requested_total{channel=email_link} = $REQ"
else
  red "✗ requested metric did not accumulate (got: $REQ, expected ≥3)"
  exit 1
fi

green ""
green "All signed-URL approval assertions passed."
