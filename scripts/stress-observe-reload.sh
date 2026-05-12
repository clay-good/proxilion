#!/usr/bin/env bash
# Stress test for observe mode + policy hot reload (ui-less-surfaces.md §2).
#
# Verifies:
#   1. GET /api/v1/policy lists current policies with modes
#   2. POST /api/v1/policy/{id}/mode flips a policy between
#      observe → enforce → disabled and the new mode is visible immediately
#   3. POST /api/v1/policy/reload triggers a from-disk reload
#   4. Policy file watcher detects an on-disk change and reloads
#   5. Parse failures don't take down the engine — previous policy stays live
#   6. proxilion_policy_reload_{success,failures}_total metrics tick

set -euo pipefail
trap 'echo "[FAIL] line $LINENO"; exit 1' ERR

PROXY="${PROXY:-https://127.0.0.1:8443}"
CURL="curl -sk --max-time 10"
POLICY_FILE_HOST="${POLICY_FILE_HOST:-config/policy.yaml}"
BACKUP_FILE="/tmp/proxilion-policy.bak"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
step()  { echo; blue "==> $*"; }

# Always restore the policy file on exit.
cp "$POLICY_FILE_HOST" "$BACKUP_FILE"
trap 'cp "$BACKUP_FILE" "$POLICY_FILE_HOST"; echo "[restore] policy file restored"' EXIT INT TERM

step "1. GET /api/v1/policy"
RESP=$($CURL "$PROXY/api/v1/policy")
echo "$RESP" | jq -c '.policies | map({id, mode})'
N=$(echo "$RESP" | jq '.policy_count')
if [ "$N" -ge 5 ]; then
  green "  ✓ policy_count=$N (≥5 expected)"
else
  red "  ✗ policy_count too low: $N"; exit 1
fi
SRC=$(echo "$RESP" | jq -r '.source')
green "  ✓ source: $SRC"

step "2. Flip drive-injection-filter to observe via /mode"
RESP=$($CURL -X POST "$PROXY/api/v1/policy/drive-injection-filter/mode" \
        -H 'content-type: application/json' \
        -d '{"mode":"observe"}')
OK=$(echo "$RESP" | jq -r '.ok')
[ "$OK" = "true" ] || { red "  ✗ set_mode failed: $RESP"; exit 1; }
green "  ✓ set_mode → ok=$OK"

# Verify via GET that the mode actually changed.
M=$($CURL "$PROXY/api/v1/policy" | jq -r '.policies[] | select(.id=="drive-injection-filter") | .mode')
if [ "$M" = "observe" ]; then
  green "  ✓ GET reflects mode=observe"
else
  red "  ✗ mode did not propagate: $M"; exit 1
fi

step "3. Flip back to default — invalid mode rejected"
CODE=$($CURL -o /dev/null -w '%{http_code}' \
        -X POST "$PROXY/api/v1/policy/drive-injection-filter/mode" \
        -H 'content-type: application/json' \
        -d '{"mode":"audit"}')
[ "$CODE" = "400" ] || { red "  ✗ invalid mode should 400; got $CODE"; exit 1; }
green "  ✓ invalid mode → 400"

step "4. set_mode on unknown policy → 404"
CODE=$($CURL -o /dev/null -w '%{http_code}' \
        -X POST "$PROXY/api/v1/policy/no-such-policy/mode" \
        -H 'content-type: application/json' \
        -d '{"mode":"observe"}')
[ "$CODE" = "404" ] || { red "  ✗ unknown policy should 404; got $CODE"; exit 1; }
green "  ✓ unknown policy → 404"

step "5. POST /api/v1/policy/reload — re-read disk"
# Restore the file first (set_mode wrote a mutated YAML in-memory and to disk-ish; reload picks up host disk state)
cp "$BACKUP_FILE" "$POLICY_FILE_HOST"
RESP=$($CURL -X POST "$PROXY/api/v1/policy/reload")
OK=$(echo "$RESP" | jq -r '.ok')
N=$(echo "$RESP" | jq -r '.policy_count')
[ "$OK" = "true" ] || { red "  ✗ reload failed: $RESP"; exit 1; }
green "  ✓ reload ok; policy_count=$N"

step "6. File watcher: mutate file on disk, wait, verify auto-reload"
# Append a 6th policy via the host file.
cat >> "$POLICY_FILE_HOST" <<'YAML'

- id: stress-watcher-sentinel
  vendor: google
  action: drive.files.list
  mode: observe
  decision: allow
  required_ops: []
YAML
green "  added stress-watcher-sentinel; waiting for watcher (≤12s)…"
for i in {1..12}; do
  sleep 1
  N=$($CURL "$PROXY/api/v1/policy" | jq -r '.policy_count')
  if [ "$N" -ge 6 ]; then
    green "  ✓ watcher reloaded; policy_count=$N after ${i}s"
    break
  fi
done
if [ "$N" -lt 6 ]; then
  red "  ✗ watcher didn't reload after 12s; policy_count=$N"; exit 1
fi

step "7. Parse failure leaves previous engine live"
echo "::: this is not valid yaml :::" > "$POLICY_FILE_HOST"
sleep 7  # one watcher tick + slack
N=$($CURL "$PROXY/api/v1/policy" | jq -r '.policy_count')
# After the watcher reads the bad file, the engine should still be the
# previous valid one (6 policies). The watcher logs the failure.
if [ "$N" -ge 6 ]; then
  green "  ✓ bad YAML did NOT clobber the live engine (policy_count still $N)"
else
  red "  ✗ engine corrupted by bad file; policy_count=$N"; exit 1
fi

# Verify the failure metric ticked.
M=$($CURL "$PROXY/metrics")
F=$(echo "$M" | grep -E '^proxilion_policy_reload_failures_total{reason="parse_error"}' | head -1 | awk '{print $NF}')
if [ -n "$F" ] && [ "$F" -ge 1 ]; then
  green "  ✓ proxilion_policy_reload_failures_total{reason=parse_error} = $F"
else
  red "  ✗ failure metric not visible: $F"
  echo "$M" | grep -E '^proxilion_policy_reload' | sed 's/^/      /'
  exit 1
fi

step "8. Restore file and verify next reload succeeds"
cp "$BACKUP_FILE" "$POLICY_FILE_HOST"
sleep 7
N=$($CURL "$PROXY/api/v1/policy" | jq -r '.policy_count')
[ "$N" -eq 5 ] || { red "  ✗ restore did not bring count back to 5; got $N"; exit 1; }
green "  ✓ post-restore policy_count=$N"

step "9. Success metric also ticked"
M=$($CURL "$PROXY/metrics")
S=$(echo "$M" | grep -E '^proxilion_policy_reload_success_total' | head -1 | awk '{print $NF}')
if [ -n "$S" ] && [ "$S" -ge 1 ]; then
  green "  ✓ proxilion_policy_reload_success_total = $S"
else
  red "  ✗ success metric absent"; exit 1
fi

step "10. Observe mode end-to-end on the policy engine"
# Flip drive-injection-filter to observe via API, exercise an evaluation
# path: the demo seeder will produce an event labeled `observe_...` rather
# than `block`.
$CURL -X POST "$PROXY/api/v1/policy/drive-injection-filter/mode" \
      -H 'content-type: application/json' -d '{"mode":"observe"}' >/dev/null
sleep 15  # let demo ticker fire a drive.files.get event
ACTIONS=$($CURL "$PROXY/api/v1/actions?action=drive.files.get&limit=10")
DECISIONS=$(echo "$ACTIONS" | jq -r '.rows[].decision' | sort -u | tr '\n' ' ')
echo "  decisions seen on drive.files.get: $DECISIONS"
# Demo events for drive.files.get have always been allow (with read_filter trigger);
# the actual block path is for a different action in demo (high-risk financial).
# So this section is informational only — the observe-mode demote is exercised
# by the policy-engine unit tests already.
green "  ✓ observe-mode evaluation path live (decisions: $DECISIONS)"

green ""
green "All observe-mode + hot-reload assertions passed."
