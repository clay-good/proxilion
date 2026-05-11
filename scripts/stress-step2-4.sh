#!/usr/bin/env bash
# scripts/stress-step2-4.sh — exercise Step 2.4 (runtime-gate vs audit
# mode enforcement) against the running docker stack.
#
# What it tests:
#   * Migration 0005 created `pic_violations` with all columns, indexes,
#     and the pic_mode CHECK constraint.
#   * Persisting both modes round-trips through Postgres.
#   * The CHECK constraint rejects invalid pic_mode strings.
#   * The full `parse_missing_atoms` parser is exercised through the
#     Rust test suite (cargo test --workspace).
#   * The executor's audit/runtime-gate dispatch is verified via
#     wiremock unit tests in pic::executor::tests (cargo test).
#   * /metrics endpoint is alive and accepts the new counter name once
#     a request fires; the series only appears after first increment,
#     so we verify endpoint reachability rather than presence.
#   * Concurrent inserts: 1000 rows × 4 parallel writers, no integrity
#     errors.

set -euo pipefail

PROXY="${PROXY_URL:-https://localhost:8443}"
PG="docker exec proxilion-dev-postgres-1 psql -U proxilion -d proxilion -At -c"

note() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; exit 1; }
pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }

# ============================================================
note "1. Schema: pic_violations exists with expected columns"
COLS=$($PG "SELECT string_agg(column_name, ',' ORDER BY ordinal_position)
            FROM information_schema.columns WHERE table_name='pic_violations';")
EXPECTED="id,request_id,session_id,p_0,vendor,action,method,path,policy_id,predecessor_pca_id,attempted_ops,missing_atoms,pic_mode,detail,at"
[ "$COLS" = "$EXPECTED" ] || fail "columns mismatch: $COLS"
pass "columns match expected layout"

note "1b. Indexes"
IDX=$($PG "SELECT indexname FROM pg_indexes WHERE tablename='pic_violations' ORDER BY indexname;")
echo "$IDX" | grep -q 'pic_violations_at' || fail "missing at index"
echo "$IDX" | grep -q 'pic_violations_session' || fail "missing session index"
echo "$IDX" | grep -q 'pic_violations_p0' || fail "missing p_0 index"
pass "all three indexes present"

note "1c. CHECK constraint rejects invalid pic_mode"
set +e
OUT=$($PG "INSERT INTO pic_violations (request_id, session_id, vendor, action, method, path, pic_mode)
           VALUES (gen_random_uuid(), gen_random_uuid(), 'google', 'test', 'GET', '/x', 'bogus_mode');" 2>&1)
set -e
echo "$OUT" | grep -q 'pic_violations_pic_mode_check' || fail "expected check constraint violation, got: $OUT"
pass "CHECK constraint enforces audit|runtime_gate"

# ============================================================
note "2. Reset table"
$PG "DELETE FROM pic_violations;" >/dev/null

note "2a. Insert audit-mode row + read it back"
RID=$(uuidgen | tr A-Z a-z); SID=$(uuidgen | tr A-Z a-z); PCA=$(uuidgen | tr A-Z a-z)
$PG "INSERT INTO pic_violations
       (request_id, session_id, p_0, vendor, action, method, path, policy_id,
        predecessor_pca_id, attempted_ops, missing_atoms, pic_mode, detail)
     VALUES
       ('$RID','$SID','alice@demo.local','google','drive.files.get','GET','/drive/v3/files/abc',
        'audit-policy','$PCA',
        ARRAY['drive:read:bob/secret']::text[],
        ARRAY['drive:read:bob/secret']::text[],
        'audit',
        'ops not subset of predecessor: missing [drive:read:bob/secret]');" >/dev/null
ROW=$($PG "SELECT pic_mode, array_length(missing_atoms,1) FROM pic_violations WHERE request_id='$RID';")
[ "$ROW" = "audit|1" ] || fail "audit row read-back mismatch: $ROW"
pass "audit row persisted and read back"

note "2b. Insert runtime_gate row"
RID2=$(uuidgen | tr A-Z a-z)
$PG "INSERT INTO pic_violations
       (request_id, session_id, vendor, action, method, path, pic_mode, attempted_ops)
     VALUES
       ('$RID2','$SID','google','gmail.messages.send','POST','/gmail/v1/users/me/messages/send',
        'runtime_gate', ARRAY['gmail:send:external']::text[]);" >/dev/null
N=$($PG "SELECT count(*) FROM pic_violations WHERE pic_mode='runtime_gate';")
[ "$N" = "1" ] || fail "runtime_gate count wrong: $N"
pass "runtime_gate row persisted"

# ============================================================
note "3. Concurrency: 4 writers × 250 rows each → 1000 total, no error"
$PG "DELETE FROM pic_violations;" >/dev/null
START=$(date +%s)
for w in 1 2 3 4; do
  ( $PG "INSERT INTO pic_violations
           (request_id, session_id, vendor, action, method, path, pic_mode, attempted_ops, missing_atoms, detail)
         SELECT gen_random_uuid(), gen_random_uuid(), 'google',
                'drive.files.get', 'GET', '/drive/v3/files/' || g,
                CASE WHEN g % 2 = 0 THEN 'audit' ELSE 'runtime_gate' END,
                ARRAY['drive:read:x']::text[],
                ARRAY['drive:read:x']::text[],
                'concurrent test ' || $w
           FROM generate_series(1,250) g;" >/dev/null ) &
done
wait
ELAPSED=$(( $(date +%s) - START ))
N=$($PG "SELECT count(*) FROM pic_violations;")
[ "$N" = "1000" ] || fail "expected 1000 concurrent rows, got $N"
AUDIT_N=$($PG "SELECT count(*) FROM pic_violations WHERE pic_mode='audit';")
RG_N=$($PG "SELECT count(*) FROM pic_violations WHERE pic_mode='runtime_gate';")
[ "$AUDIT_N" = "500" ] || fail "audit half-split wrong: $AUDIT_N"
[ "$RG_N" = "500" ] || fail "runtime_gate half-split wrong: $RG_N"
pass "1000 concurrent inserts in ${ELAPSED}s, 500/500 split clean"

note "3b. Query patterns the SIEM forwarder will use"
RECENT=$($PG "SELECT count(*) FROM pic_violations WHERE at > now() - interval '1 minute';")
[ "$RECENT" -ge 1000 ] || fail "time-window query empty"
pass "time-window query returns $RECENT rows"

# ============================================================
note "4. Rust test suite (executor + parser + violations)"
( cd "$(git rev-parse --show-toplevel)" && cargo test -q --workspace 2>&1 | tail -15 ) \
  || fail "cargo test failed"
pass "cargo test --workspace clean"

# ============================================================
note "5. Proxy /metrics endpoint reachable"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' "$PROXY/metrics")
[ "$CODE" = "200" ] || fail "/metrics should 200; got $CODE"
pass "/metrics returns 200 (proxilion_pic_violations_total registers on first increment)"

# ============================================================
note "6. Cleanup"
$PG "DELETE FROM pic_violations;" >/dev/null
pass "table cleared"

# ============================================================
printf '\n\033[1;32m=== ALL STEP 2.4 CHECKS PASSED ===\033[0m\n'
