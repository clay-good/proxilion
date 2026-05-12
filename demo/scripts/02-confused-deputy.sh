#!/usr/bin/env bash
# Scenario 2 — Confused-deputy attack (the headline).
#
# Mints a PCA_0 for alice@demo.local with a narrow ops set (her own files
# + engineering). Then attempts to mint a successor PCA whose ops include
# `drive:write:bob/finance/secret.docx` — Bob's stuff, never granted to
# alice. The Trust Plane refuses on monotonicity grounds.
#
# This is non-expressible by construction. There is no policy to bypass;
# the PIC invariant lives in the Trust Plane code.

source "$(dirname "$0")/_lib.sh"
require curl jq docker uuidgen xxd

hdr "Mint PCA_0: alice@demo.local can read her own files + engineering"
mint_pca0 '[
  "drive:read:alice@demo.local",
  "drive:read:engineering"
]'
say "  p_0=$PCA0_P0"
say "  ops=$(jq -r 'join(", ")' <<<"$PCA0_OPS_JSON")"

hdr "Seed a synthetic blocked action that attempts ESCALATION"
# We use the live `/api/v1/blocked/{id}/approve` flow because it asks the
# Trust Plane to mint a successor with operator-supplied ops. That mirrors
# what an attacker who somehow got into the operator console could try.
SID=$(uuidgen | tr 'A-Z' 'a-z')
BLOCKED_ID=$(uuidgen | tr 'A-Z' 'a-z')
pg "INSERT INTO blocked_actions
      (id, request_id, session_id, p_0, vendor, action, method, path, layer,
       policy_id, detail, predecessor_pca_id, requested_ops, status, expires_at)
    VALUES ('$BLOCKED_ID', gen_random_uuid(), '$SID', '$PCA0_P0', 'google',
            'drive.files.get', 'GET', '/drive/v3/files/bob-secret',
            'policy', 'demo-deputy', 'attacker tries to read bob/finance',
            '$PCA0_ID',
            ARRAY['drive:write:bob/finance/secret.docx']::text[],
            'pending', now() + interval '5 minutes');" >/dev/null

hdr "Attempting override (attacker tries to bypass)…"
RESP=$($CURL -w '\n%{http_code}' -X POST "$PROXY/api/v1/blocked/$BLOCKED_ID/approve" \
  -H 'content-type: application/json' \
  -d '{"justification":"the attacker tries to escalate to bobs files via override"}')
CODE=$(echo "$RESP" | tail -n 1)
BODY=$(echo "$RESP" | sed '$d')
printf '\n'
echo "$BODY" | jq -c .
printf '\n'

if [ "$CODE" = "422" ]; then
  green "Trust Plane refused with HTTP 422 — monotonicity invariant held."
  say "  ops 'drive:write:bob/finance/secret.docx' is NOT a subset of PCA_0.ops"
  say "  The successor was never minted. No chain exists for the attempt."
else
  red "Expected 422; got $CODE"
  exit 1
fi

hdr "Confirm: the override PCA was never persisted"
N=$(pg "SELECT count(*) FROM pca_cache WHERE predecessor_id='$PCA0_ID';")
say "  successor PCAs chained from PCA_0: $N (expected 0)"

hdr "Audit trail: the blocked row remains pending; SOC can review"
ROW=$(pg "SELECT id, status, layer, requested_ops FROM blocked_actions WHERE id='$BLOCKED_ID';")
say "  $ROW"

green ""
green "Confused-deputy attack non-expressible by construction."
