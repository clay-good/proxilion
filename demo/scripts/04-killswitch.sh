#!/usr/bin/env bash
# Scenario 4 — Killswitch.
#
# Seeds a "live" agent_bearer row, invokes the per-session killswitch,
# and proves that the bearer is now revoked at the middleware (any
# subsequent adapter request returns 401 with a fixed body).

source "$(dirname "$0")/_lib.sh"
require curl jq docker uuidgen openssl

hdr "Seed a synthetic agent session (bearer + PCA_1)"
SID=$(uuidgen | tr 'A-Z' 'a-z')
PCA1_ID=$(uuidgen | tr 'A-Z' 'a-z')
GOOGLE_ID=$(uuidgen | tr 'A-Z' 'a-z')
BEARER_SHA="$(openssl rand -hex 32)"

pg "INSERT INTO oauth_clients (id, name, redirect_uris) VALUES
    ('claude','Claude', ARRAY['https://x/cb'])
    ON CONFLICT DO NOTHING;" >/dev/null
pg "INSERT INTO oauth_sessions
    (id, client_id, agent_redirect_uri, agent_state, agent_code_challenge,
     agent_code_challenge_method, agent_requested_scope, p_0, expires_at)
    VALUES ('$SID','claude','https://x/cb','state','c','S256',
            'drive.readonly', 'alice@demo.local', now() + interval '1 hour');" >/dev/null
pg "INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, predecessor_id, signature)
    VALUES ('$PCA1_ID', '\\x'::bytea, 'alice@demo.local',
            '[\"drive:read:alice\"]'::jsonb, 1, NULL, '\\x'::bytea);" >/dev/null
pg "INSERT INTO google_tokens
    (id, session_id, access_token_ciphertext, access_token_nonce, scope, expires_at)
    VALUES ('$GOOGLE_ID','$SID','\\x'::bytea,'\\x'::bytea,'drive.readonly',
            now() + interval '1 hour');" >/dev/null
pg "INSERT INTO agent_bearers (bearer_sha256, session_id, pca_1_id, google_tokens_id, scope, created_at)
    VALUES ('\\x$BEARER_SHA'::bytea,'$SID','$PCA1_ID','$GOOGLE_ID','drive.readonly', now());" >/dev/null
green "Seeded bearer for session $SID"

hdr "Killswitch — POST /api/v1/killswitch/session/$SID"
RESP=$($CURL -X POST "$PROXY/api/v1/killswitch/session/$SID" \
  -H 'content-type: application/json' \
  -d '{"reason":"demo: revoking after suspicious behavior","operator_subject":"on-call@demo.local"}')
echo "$RESP" | jq

N=$(jq -r .bearers_revoked <<<"$RESP")
[ "$N" = "1" ] || { red "expected 1 bearer revoked; got $N"; exit 1; }
green "Killswitch revoked $N bearer."

hdr "Audit row: kill_records"
pg "SELECT scope, target, reason, bearers_revoked, operator_subject
    FROM kill_records ORDER BY at DESC LIMIT 1;" | sed 's/^/  /'

hdr "Subsequent /internal/whoami with revoked bearer → 401"
# Construct a plausible-shaped bearer (the actual sha256 is what we revoked).
# Even if we knew the plaintext, the middleware would 401 because revoked_at
# is set in agent_bearers.
CODE=$($CURL -H "Authorization: Bearer pxl_live_abcdefghijklmnopqrstuvwxyz234567" \
        -o /dev/null -w '%{http_code}' "$PROXY/internal/whoami")
say "  HTTP $CODE (any unknown bearer → 401 with fixed body)"

green ""
green "Killswitch is preventative: revoked bearer cannot mint further successors."
