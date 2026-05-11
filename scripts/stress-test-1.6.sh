#!/usr/bin/env bash
# Stress test for §1.6 API surface and the M1 data flow that feeds it.
#
# Covers:
#   - /healthz, /api/v1/setup/status
#   - /api/v1/actions       (paginated envelope + filters)
#   - /api/v1/actions/recent (raw-array back-compat)
#   - /api/v1/actions/stream (SSE: open, receive, close)
#   - /api/v1/actions/:id   (happy + 404 + bad uuid)
#   - /api/v1/sessions/:id/chain (happy + unknown session)
#   - /api/v1/pca/:id, /api/v1/pca/:id/verify (existing §1.5)
#   - Error envelope shape on 4xx/5xx
#   - Concurrent load against /actions

set -u
BASE="${BASE:-https://127.0.0.1:18443}"
CURL="curl -sk -o /tmp/proxilion-stress.body -w %{http_code}"
PASS=0; FAIL=0; FAILS=()

note()  { printf "\n\033[36m== %s ==\033[0m\n" "$*"; }
ok()    { printf "  \033[32mPASS\033[0m %s\n" "$*"; PASS=$((PASS+1)); }
bad()   { printf "  \033[31mFAIL\033[0m %s\n" "$*"; FAIL=$((FAIL+1)); FAILS+=("$*"); }

expect_status() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then ok "$label → $got"; else bad "$label (want $want, got $got; body: $(head -c 240 /tmp/proxilion-stress.body))"; fi
}

note "1. /healthz and /api/v1/setup/status"
s=$($CURL "$BASE/healthz");                 expect_status "healthz"       200 "$s"
ready=$(jq -r .ready /tmp/proxilion-stress.body 2>/dev/null || echo "?")
if [[ "$ready" == "true" || "$ready" == "false" ]]; then ok "healthz.ready is boolean ($ready)"; else bad "healthz.ready not boolean: $ready"; fi
s=$($CURL "$BASE/api/v1/setup/status");     expect_status "setup/status"  200 "$s"

note "2. /api/v1/actions envelope"
s=$($CURL "$BASE/api/v1/actions?limit=3");  expect_status "list limit=3"  200 "$s"
shape=$(jq -r 'has("rows") and has("next_before")' /tmp/proxilion-stress.body 2>/dev/null || echo "no")
if [[ "$shape" == "true" ]]; then ok "envelope has rows + next_before"; else bad "envelope shape wrong"; fi
n=$(jq '.rows | length' /tmp/proxilion-stress.body)
[[ "$n" -le 3 ]] && ok "limit honored ($n ≤ 3)" || bad "limit not honored: $n"

# Pagination chain follows next_before
nb=$(jq -r '.next_before // empty' /tmp/proxilion-stress.body)
if [[ -n "$nb" ]]; then
  s=$($CURL "$BASE/api/v1/actions?limit=3&before=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$nb")")
  expect_status "list page2" 200 "$s"
  n2=$(jq '.rows | length' /tmp/proxilion-stress.body)
  ok "page2 returned $n2 rows"
fi

note "3. Filters"
for f in "decision=allow" "decision=block" "vendor=google" "action=drive.files.get" "p_0=user:alice@demo.local" "session_id=00000000-0000-0000-0000-000000000000"; do
  s=$($CURL "$BASE/api/v1/actions?$f&limit=5")
  expect_status "filter $f" 200 "$s"
done

note "4. Limit clamping & bad inputs"
s=$($CURL "$BASE/api/v1/actions?limit=99999"); expect_status "limit 99999 clamps"  200 "$s"
n=$(jq '.rows | length' /tmp/proxilion-stress.body)
[[ "$n" -le 500 ]] && ok "clamped to ≤500 ($n)" || bad "not clamped: $n"
s=$($CURL "$BASE/api/v1/actions?limit=0");     expect_status "limit 0 clamps to 1" 200 "$s"
s=$($CURL "$BASE/api/v1/actions?limit=abc");   expect_status "limit=abc → 400"     400 "$s"
s=$($CURL "$BASE/api/v1/actions?session_id=not-a-uuid"); expect_status "session_id bad uuid → 400" 400 "$s"
s=$($CURL "$BASE/api/v1/actions?before=garbage");        expect_status "before garbage → 400"      400 "$s"

note "5. /api/v1/actions/recent backward compat"
s=$($CURL "$BASE/api/v1/actions/recent?limit=2"); expect_status "recent" 200 "$s"
is_array=$(jq -r 'type=="array"' /tmp/proxilion-stress.body 2>/dev/null || echo "no")
[[ "$is_array" == "true" ]] && ok "recent returns raw array" || bad "recent not raw array"

note "6. /api/v1/actions/:id"
first_id=$(curl -sk "$BASE/api/v1/actions?limit=1" | jq -r '.rows[0].id')
if [[ -n "$first_id" && "$first_id" != "null" ]]; then
  s=$($CURL "$BASE/api/v1/actions/$first_id")
  expect_status "actions/$first_id" 200 "$s"
  has_chain=$(jq 'has("chain")' /tmp/proxilion-stress.body)
  [[ "$has_chain" == "true" ]] && ok "detail has chain field" || bad "detail missing chain"
  chain_len=$(jq '.chain | length' /tmp/proxilion-stress.body)
  ok "chain length = $chain_len"
  # If chain is non-empty, verify root → leaf ordering (hop ascending, first hop=0)
  if [[ "$chain_len" -gt 0 ]]; then
    first_hop=$(jq '.chain[0].hop' /tmp/proxilion-stress.body)
    [[ "$first_hop" == "0" ]] && ok "chain[0].hop == 0 (root first)" || bad "chain[0].hop != 0 (got $first_hop)"
    asc=$(jq '[.chain[].hop] | . == (sort)' /tmp/proxilion-stress.body)
    [[ "$asc" == "true" ]] && ok "hops monotonically ascending" || bad "hops not ascending"
  fi
fi
s=$($CURL "$BASE/api/v1/actions/00000000-0000-0000-0000-000000000000");
expect_status "actions/<unknown uuid> → 404" 404 "$s"
err_code=$(jq -r '.code // empty' /tmp/proxilion-stress.body)
[[ "$err_code" == "not_found" ]] && ok "error envelope code=not_found" || bad "wrong error code: $err_code"
s=$($CURL "$BASE/api/v1/actions/not-a-uuid"); expect_status "actions/<bad-uuid> → 400" 400 "$s"

note "7. /api/v1/sessions/:id/chain"
sid=$(curl -sk "$BASE/api/v1/actions?limit=20" | jq -r '[.rows[] | select(.session_id != null) | .session_id][0]')
if [[ -n "$sid" && "$sid" != "null" ]]; then
  s=$($CURL "$BASE/api/v1/sessions/$sid/chain")
  expect_status "sessions/$sid/chain" 200 "$s"
  has=$(jq 'has("chain") and has("session_id")' /tmp/proxilion-stress.body)
  [[ "$has" == "true" ]] && ok "session chain shape ok" || bad "session chain shape wrong"
fi
s=$($CURL "$BASE/api/v1/sessions/00000000-0000-0000-0000-000000000000/chain")
expect_status "sessions/<unknown>/chain → 200 with empty chain" 200 "$s"
empty=$(jq '.chain | length == 0' /tmp/proxilion-stress.body)
[[ "$empty" == "true" ]] && ok "unknown session yields empty chain" || bad "unknown session not empty"
s=$($CURL "$BASE/api/v1/sessions/bad-uuid/chain"); expect_status "sessions/<bad-uuid> → 400" 400 "$s"

note "8. /api/v1/pca/:id"
# Demo seeds synthetic leaf_pca_ids in action_events WITHOUT populating
# pca_cache, so /pca/:id for demo leaves correctly returns 404. We exercise:
#   - explicit-unknown UUID → 404
#   - /verify on any UUID → 200 with intact:false (verifier reports the break)
s=$($CURL "$BASE/api/v1/pca/00000000-0000-0000-0000-000000000000"); expect_status "pca/<unknown> → 404" 404 "$s"
err_code=$(jq -r '.code // empty' /tmp/proxilion-stress.body)
[[ "$err_code" == "not_found" ]] && ok "404 envelope has code=not_found" || bad "wrong error code: $err_code"
s=$($CURL "$BASE/api/v1/pca/00000000-0000-0000-0000-000000000000/verify"); expect_status "pca/<unknown>/verify → 200" 200 "$s"
intact=$(jq -r '.intact' /tmp/proxilion-stress.body)
[[ "$intact" == "false" ]] && ok "/verify on unknown reports intact:false" || bad "/verify intact: $intact"

note "9. SSE stream opens and emits events"
# Stream stays open & gets at least one "action" event from the demo ticker
# (which fires every 6–12s). Wait up to 15s.
curl -sk -N --max-time 15 "$BASE/api/v1/actions/stream" -o /tmp/proxilion-sse.txt 2>/dev/null || true
events=$(grep -c "^event:" /tmp/proxilion-sse.txt 2>/dev/null || echo 0)
if [[ "$events" -ge 1 ]]; then ok "SSE saw $events event(s)"; else bad "SSE saw 0 events in 15s (demo ticker?)"; fi

note "10. Concurrent load: 50 parallel /actions reqs"
codes=$(seq 50 | xargs -I{} -P 25 curl -sk -o /dev/null -w "%{http_code}\n" "$BASE/api/v1/actions?limit=10")
ok_count=$(echo "$codes" | grep -c "^200$")
fail_count=$(echo "$codes" | grep -vc "^200$" || true)
if [[ "$ok_count" == "50" ]]; then ok "50/50 OK under load"; else bad "$fail_count/$50 non-200 under load"; fi

note "11. Path injection / overlong / weird headers"
s=$($CURL "$BASE/api/v1/actions/../setup/status"); expect_status "path traversal attempt"  200 "$s"
# overlong p_0 (URL-encoded 4k chars)
LONG=$(python3 -c "print('a'*4000)")
s=$($CURL "$BASE/api/v1/actions?p_0=$LONG&limit=1"); expect_status "4k p_0 filter" 200 "$s"
n=$(jq '.rows | length' /tmp/proxilion-stress.body)
[[ "$n" == "0" ]] && ok "overlong p_0 yielded empty (no SQL error)" || bad "unexpected rows for overlong p_0"
# header injection — sqlx parameterizes so this should just be a no-match
s=$($CURL "$BASE/api/v1/actions?vendor=google%27%3B%20DROP%20TABLE%20action_events%3B%20--&limit=1"); expect_status "SQLi attempt → 200" 200 "$s"
n=$(jq '.rows | length' /tmp/proxilion-stress.body)
[[ "$n" == "0" ]] && ok "SQLi-shaped vendor returned 0 rows (parameterized)" || bad "SQLi attempt returned rows: $n"
s=$($CURL -X POST "$BASE/api/v1/actions"); expect_status "POST /actions → 405" 405 "$s"

note "----"
echo "PASSED: $PASS   FAILED: $FAIL"
for f in "${FAILS[@]:-}"; do [[ -n "$f" ]] && echo "  - $f"; done
[[ "$FAIL" == 0 ]] && exit 0 || exit 1
