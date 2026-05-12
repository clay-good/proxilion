#!/usr/bin/env bash
# Scenario 3 — Blocked Layer-B action → operator override → attested PCA branch.
#
# This is the happy-path companion to scenario 2. Alice's agent attempts
# a legitimate action that a Layer-B policy blocked (e.g. external-recipient
# Gmail send). An operator reviews and approves with a justification. The
# override mints a successor PCA chained off PCA_0 — auditable forever.

source "$(dirname "$0")/_lib.sh"
require curl jq docker uuidgen xxd

hdr "Mint PCA_0 with ops that DO cover the action"
# mock-okta only emits drive:read ops; we exercise the override flow on a
# Drive read that Layer-B blocked (e.g. read of a flagged document). The
# override is what matters here — the specific Layer-B rule is interchangeable.
mint_pca0 '[
  "drive:read:alice@demo.local"
]'
say "  p_0=$PCA0_P0"

hdr "Seed blocked Drive read (Layer-B policy gated)"
SID=$(uuidgen | tr 'A-Z' 'a-z')
BLOCKED_ID=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$BLOCKED_ID', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'drive.files.get', 'GET',
            '/drive/v3/files/quarterly-report', 'policy',
            'drive-injection-filter',
            'read_filter quarantined: ignore previous instructions',
            '$PCA0_ID',
            ARRAY['drive:read:alice@demo.local']::text[],
            'pending', now() + interval '30 minutes');" >/dev/null

say "  blocked_id=$BLOCKED_ID"

hdr "Operator approves with justification"
RESP=$($CURL -X POST "$PROXY/api/v1/blocked/$BLOCKED_ID/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"verified with alice over slack: legitimate customer reply","approver_subject":"on-call@demo.local"}')
echo "$RESP" | jq -c .
OVR_PCA=$(jq -r .override_pca_id <<<"$RESP")
HOP=$(jq -r .hop <<<"$RESP")
[ "$HOP" = "1" ] || { red "expected hop=1, got $HOP"; exit 1; }

green "Override PCA minted: $OVR_PCA at hop=$HOP"

hdr "Walk the chain — override PCA chains directly from PCA_0"
PRED=$(pg "SELECT predecessor_id FROM pca_cache WHERE pca_id='$OVR_PCA';")
say "  override PCA predecessor: $PRED"
say "  expected:                 $PCA0_ID"
[ "$PRED" = "$PCA0_ID" ] || { red "predecessor mismatch"; exit 1; }

hdr "Verify the override chain end-to-end"
$CURL "$PROXY/api/v1/pca/$OVR_PCA/verify" | jq

hdr "Audit trail: blocked row recorded with approver + override PCA id"
pg "SELECT status, approver_subject, override_pca_id, justification
    FROM blocked_actions WHERE id='$BLOCKED_ID';" \
  | tr '|' '\n' | nl -ba | sed 's/^/  /'

green ""
green "Layer-B block → human approval → attested override chain."
