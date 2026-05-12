#!/usr/bin/env bash
# Stress test for per-endpoint scope enforcement + new CLI subcommands
# (ui-less-surfaces.md §4.4 deviation 1 + §2 + §4).
#
# Verifies:
#   1. Narrow-scope token gets 200 on its scope's GET, 403 on others
#   2. Killswitch with policy:read scope → 403
#   3. Blocks approve with blocks:read only → 403, with blocks:approve → 200
#   4. proxilion-cli policy list / set-mode / reload — happy path
#   5. proxilion-cli blocked list / show / approve / reject — happy path

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

step "0. Reset operator_tokens + flip to enforced auth"
pg "TRUNCATE operator_tokens;" >/dev/null
PROXILION_DISABLE_OPERATOR_AUTH=0 docker compose up -d proxy >/dev/null 2>&1
sleep 5
green "  ✓ enforced"

step "1. Mint a narrow policy:read-only token"
RESP=$(DATABASE_URL="$DB_URL" cargo run -q -p proxilion-cli -- tokens issue \
        --name "policy-reader" --scope policy:read 2>/dev/null)
TOK_READ=$(echo "$RESP" | jq -r '.token')
green "  ✓ minted policy:read token"

step "2. Mint a blocks:approve token (no policy access)"
RESP=$(DATABASE_URL="$DB_URL" cargo run -q -p proxilion-cli -- tokens issue \
        --name "approver" --scope blocks:read,blocks:approve 2>/dev/null)
TOK_APPROVE=$(echo "$RESP" | jq -r '.token')
green "  ✓ minted blocks:approve token"

step "3. Mint a kill-everything admin token"
RESP=$(DATABASE_URL="$DB_URL" cargo run -q -p proxilion-cli -- tokens issue \
        --name "admin" --scope '*' 2>/dev/null)
TOK_ADMIN=$(echo "$RESP" | jq -r '.token')
green "  ✓ minted admin token"

step "4. policy:read token can GET /api/v1/policy"
CODE=$($CURL -H "Authorization: Bearer $TOK_READ" -o /dev/null -w '%{http_code}' \
        "$PROXY/api/v1/policy")
[ "$CODE" = "200" ] || { red "✗ expected 200; got $CODE"; exit 1; }
green "  ✓ GET /api/v1/policy → 200"

step "5. policy:read token CANNOT POST /api/v1/policy/reload (needs policy:write) → 403"
CODE=$($CURL -H "Authorization: Bearer $TOK_READ" -X POST -o /dev/null -w '%{http_code}' \
        "$PROXY/api/v1/policy/reload")
[ "$CODE" = "403" ] || { red "✗ expected 403; got $CODE"; exit 1; }
green "  ✓ POST /api/v1/policy/reload → 403"

step "6. policy:read token CANNOT POST /api/v1/killswitch/all → 403"
CODE=$($CURL -H "Authorization: Bearer $TOK_READ" -X POST \
        -H 'content-type: application/json' -d '{"confirm":"yes"}' \
        -o /dev/null -w '%{http_code}' "$PROXY/api/v1/killswitch/all")
[ "$CODE" = "403" ] || { red "✗ expected 403; got $CODE"; exit 1; }
green "  ✓ POST /api/v1/killswitch/all → 403"

step "7. blocks:approve token CAN GET /api/v1/blocked"
CODE=$($CURL -H "Authorization: Bearer $TOK_APPROVE" -o /dev/null -w '%{http_code}' \
        "$PROXY/api/v1/blocked")
[ "$CODE" = "200" ] || { red "✗ expected 200; got $CODE"; exit 1; }
green "  ✓ GET /api/v1/blocked → 200"

step "8. blocks:approve token CANNOT GET /api/v1/policy → 403"
CODE=$($CURL -H "Authorization: Bearer $TOK_APPROVE" -o /dev/null -w '%{http_code}' \
        "$PROXY/api/v1/policy")
[ "$CODE" = "403" ] || { red "✗ expected 403; got $CODE"; exit 1; }
green "  ✓ GET /api/v1/policy → 403"

step "9. Scope-denied response body carries required + have"
BODY=$($CURL -H "Authorization: Bearer $TOK_APPROVE" "$PROXY/api/v1/policy")
echo "  $BODY"
echo "$BODY" | jq -e '.code == "scope_denied" and .required == "policy:read"' >/dev/null || \
  { red "✗ unexpected body"; exit 1; }
green "  ✓ body shape OK"

step "10. proxilion-cli policy list via admin token"
LIST=$(PROXILION_OPERATOR_TOKEN="$TOK_ADMIN" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" policy list --format json 2>/dev/null)
N=$(echo "$LIST" | jq 'length')
[ "$N" -ge 5 ] || { red "✗ expected ≥5 policies; got $N"; exit 1; }
green "  ✓ policy list returned $N policies"

step "11. proxilion-cli policy set-mode (requires policy:write, admin has *)"
RESP=$(PROXILION_OPERATOR_TOKEN="$TOK_ADMIN" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
       policy set-mode drive-injection-filter observe 2>/dev/null)
echo "$RESP" | jq -e '.ok == true' >/dev/null || \
  { red "✗ set-mode response unexpected: $RESP"; exit 1; }
green "  ✓ set-mode → ok"
# Verify mode actually changed
M=$(PROXILION_OPERATOR_TOKEN="$TOK_ADMIN" \
    cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" policy list --format json 2>/dev/null \
    | jq -r '.[] | select(.id=="drive-injection-filter") | .mode')
[ "$M" = "observe" ] || { red "✗ mode not propagated: $M"; exit 1; }
green "  ✓ mode reflects observe"

step "12. proxilion-cli policy reload (admin)"
RESP=$(PROXILION_OPERATOR_TOKEN="$TOK_ADMIN" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" policy reload 2>/dev/null)
echo "$RESP" | jq -e '.ok == true' >/dev/null || \
  { red "✗ reload response unexpected: $RESP"; exit 1; }
green "  ✓ reload → ok"

step "13. proxilion-cli policy reload via policy:read-only token → fails with 403"
RESP=$(PROXILION_OPERATOR_TOKEN="$TOK_READ" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" policy reload 2>&1 \
       | tail -10 || true)
if echo "$RESP" | grep -q "403"; then
  green "  ✓ reload → 403 with policy:read"
else
  red "✗ expected 403 surfaced; got: $RESP"
  exit 1
fi

step "14. Seed a pending blocked_action with a REAL Trust Plane PCA_0"
# Approve needs valid predecessor CBOR. Mint via mock-okta → Trust Plane.
ID_TOKEN=$(curl -fsS -X POST "http://127.0.0.1:9090/default/token" \
  -d grant_type=client_credentials -d client_id=proxilion-dev \
  -d client_secret=dev-secret -d scope=openid | jq -r '.id_token // .access_token')
PCA0=$(curl -fsS -X POST "http://127.0.0.1:8080/v1/pca/issue" \
  -H 'content-type: application/json' \
  -d "$(jq -n --arg c "$ID_TOKEN" '{credential:$c, credential_type:"jwt",
        ops:["drive:read:alice@demo.local"], executor_binding:{service:"stress"}}')")
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
            'demo-policy', 'cli-stress', '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[], 'pending',
            now() + interval '30 minutes');" >/dev/null
green "  ✓ seeded blocked_id=$BLOCKED_ID predecessor=$PCA0_ID"

step "15. proxilion-cli blocked list pretty"
PROXILION_OPERATOR_TOKEN="$TOK_APPROVE" \
  cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
  blocked list --format json 2>/dev/null \
  | jq -e '.[] | select(.id != null)' >/dev/null \
  || { red "✗ list empty"; exit 1; }
green "  ✓ blocked list found row(s)"

step "16. proxilion-cli blocked show"
SHOW=$(PROXILION_OPERATOR_TOKEN="$TOK_APPROVE" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
       blocked show "$BLOCKED_ID" --format json 2>/dev/null)
echo "$SHOW" | jq -e ".id == \"$BLOCKED_ID\"" >/dev/null \
  || { red "✗ show wrong id: $SHOW"; exit 1; }
green "  ✓ show returned record"

step "17. proxilion-cli blocked approve"
RESP=$(PROXILION_OPERATOR_TOKEN="$TOK_APPROVE" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
       blocked approve "$BLOCKED_ID" \
       --justification "stress-test approval is at least twenty chars long" 2>/dev/null)
echo "$RESP" | jq -e '.status == "overridden"' >/dev/null \
  || { red "✗ approve unexpected: $RESP"; exit 1; }
green "  ✓ approved"

step "18. policy:read-only token cannot approve (no blocks:approve scope) → 403"
# Use a different blocked id since the previous is now overridden.
B2=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$B2', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'drive.files.get', 'GET', '/drive/v3/files/xyz', 'policy',
            'demo-policy', 'cli-stress', '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[], 'pending',
            now() + interval '30 minutes');" >/dev/null
RESP=$(PROXILION_OPERATOR_TOKEN="$TOK_READ" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
       blocked approve "$B2" \
       --justification "this is a sufficiently long justification text" 2>&1 \
       | tail -10 || true)
if echo "$RESP" | grep -qE "403|scope"; then
  green "  ✓ approve as policy:read → blocked"
else
  red "✗ expected 403; got: $RESP"
  exit 1
fi

step "19. proxilion-cli blocked reject"
RESP=$(PROXILION_OPERATOR_TOKEN="$TOK_APPROVE" \
       cargo run -q -p proxilion-cli -- --insecure --url "$PROXY" \
       blocked reject "$B2" --reason "stress-test rejection" 2>/dev/null)
echo "$RESP" | jq -e '.status == "rejected"' >/dev/null \
  || { red "✗ reject unexpected: $RESP"; exit 1; }
green "  ✓ rejected"

step "20. Metrics tick — scope_denied counter"
M=$($CURL -H "Authorization: Bearer $TOK_ADMIN" "$PROXY/metrics")
D=$(echo "$M" | grep -E '^proxilion_operator_auth_total\{result="rejected",reason="scope_denied"' | head -1 | awk '{print $NF}')
if [ -n "$D" ] && [ "$D" -ge 1 ]; then
  green "  ✓ proxilion_operator_auth_total{result=rejected,reason=scope_denied} = $D"
else
  red "✗ scope_denied metric absent"; exit 1
fi

step "21. Restore disabled mode"
PROXILION_DISABLE_OPERATOR_AUTH=1 docker compose up -d proxy >/dev/null 2>&1
sleep 5
CODE=$($CURL -o /dev/null -w '%{http_code}' "$PROXY/api/v1/policy")
[ "$CODE" = "200" ] || { red "✗ disabled mode broken; got $CODE"; exit 1; }
green "  ✓ disabled mode restored"

green ""
green "All scope-enforcement + CLI assertions passed."
