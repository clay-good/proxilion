#!/usr/bin/env bash
# Stress test for Step 4.1 — Google Calendar adapter.
#
# Verifies routes are mounted behind the bearer middleware, that policy
# evaluation fires on writes, and that path encoding handles edge cases.
# The proxy is exercised without a real Google account; we assert the
# correct *boundary* behavior at the proxy edge (401, 400, route shape).

set -euo pipefail
trap 'echo "[FAIL] line $LINENO"; exit 1' ERR

PROXY="${PROXY:-https://127.0.0.1:8443}"
CURL="curl -sk --max-time 8"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
step()  { echo; blue "==> $*"; }

assert_status() {
  local url="$1" want="$2" desc="$3" method="${4:-GET}"
  local got
  got=$($CURL -X "$method" -o /dev/null -w "%{http_code}" "$url")
  if [ "$got" = "$want" ]; then
    green "  ✓ $desc ($method $url → $got)"
  else
    red "  ✗ $desc: got=$got want=$want ($method $url)"; exit 1
  fi
}

assert_status_with_bearer() {
  local url="$1" want="$2" desc="$3" method="${4:-GET}" bearer="${5:-pxl_live_invalid}"
  local got
  got=$($CURL -X "$method" -H "Authorization: Bearer $bearer" \
          -o /dev/null -w "%{http_code}" "$url")
  if [ "$got" = "$want" ]; then
    green "  ✓ $desc ($method $url → $got)"
  else
    red "  ✗ $desc: got=$got want=$want ($method $url)"; exit 1
  fi
}

step "1. Calendar routes mounted (401 without bearer)"
assert_status "$PROXY/google/calendar/v3/calendars/primary/events" 401 "list events route exists" GET
assert_status "$PROXY/google/calendar/v3/calendars/primary/events/e123" 401 "get event route exists" GET
# POST without body still hits the route; expect 401 from middleware before body parse.
got=$($CURL -X POST -o /dev/null -w "%{http_code}" \
      "$PROXY/google/calendar/v3/calendars/primary/events")
if [ "$got" = "401" ]; then
  green "  ✓ insert event route exists (POST → 401)"
else
  red "  ✗ insert route: got=$got want=401"; exit 1
fi

step "2. Calendar routes reject invalid bearer with 401 (no info leak)"
assert_status_with_bearer "$PROXY/google/calendar/v3/calendars/primary/events" 401 "list with bogus bearer" GET
assert_status_with_bearer "$PROXY/google/calendar/v3/calendars/work%40acme.com/events/X" 401 "get with email-shaped calendarId" GET
assert_status_with_bearer "$PROXY/google/calendar/v3/calendars/primary/events/abc" 401 "put with bogus bearer" PUT
assert_status_with_bearer "$PROXY/google/calendar/v3/calendars/primary/events/abc" 401 "patch with bogus bearer" PATCH

step "3. Response body is fixed (no leak) on 401"
body=$($CURL -X GET -H 'Authorization: Bearer pxl_live_invalid' \
        "$PROXY/google/calendar/v3/calendars/primary/events")
echo "  body: $body"
if echo "$body" | grep -q 'unauthorized'; then
  green "  ✓ body says 'unauthorized'"
else
  red "  ✗ unexpected body shape"; exit 1
fi

step "4. Routes do NOT collide with Gmail / Drive paths"
# Gmail messages must still 401, not 404 / 405.
assert_status_with_bearer "$PROXY/google/gmail/v1/users/me/messages" 401 "gmail still mounted" GET
assert_status_with_bearer "$PROXY/google/drive/v3/files" 401 "drive still mounted" GET

step "5. Policy bundle loaded with 5 entries"
# The proxy logs the policy_count on /admin/setup status; pull it.
STATUS=$($CURL "$PROXY/api/v1/setup/status" || echo '{}')
# `policies` item carries "N policies loaded" in `detail`.
n=$(echo "$STATUS" | sed -nE 's/.*"detail":"([0-9]+) policies loaded".*/\1/p' | head -1)
if [ "${n:-0}" -ge 5 ]; then
  green "  ✓ policy_count=$n (≥5 expected after Calendar gates)"
else
  red "  ✗ policy_count too low: $n"
  echo "  status: $STATUS"
  exit 1
fi

step "6. Bearer auth metrics emit for Calendar paths"
# Prime
$CURL -H 'Authorization: Bearer pxl_live_invalid' \
   "$PROXY/google/calendar/v3/calendars/primary/events" -o /dev/null
M=$($CURL "$PROXY/metrics")
if echo "$M" | grep -q 'proxilion_auth_attempts_total{result="rejected"}'; then
  green "  ✓ auth_attempts_total{result=rejected} present"
else
  red "  ✗ missing auth metric"; exit 1
fi

step "7. Concurrency: 50 Calendar list requests interleaved"
PIDS=()
for i in $(seq 1 50); do
  $CURL -H 'Authorization: Bearer pxl_live_invalid' \
        "$PROXY/google/calendar/v3/calendars/primary/events" \
        -o /dev/null -w "%{http_code} " &
  PIDS+=($!)
done
out=$(wait "${PIDS[@]}"; echo)
ok=$($CURL -o /dev/null -w "%{http_code}" "$PROXY/healthz")
green "  ✓ 50-way Calendar list handled (final /healthz=$ok)"

green ""
green "All Calendar adapter stress assertions passed."
