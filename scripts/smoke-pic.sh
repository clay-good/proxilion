#!/usr/bin/env bash
# scripts/smoke-pic.sh — end-to-end smoke test for the M0 stack.
#
# Walks the mock-okta token-issuance flow, posts the resulting id_token to
# Trust Plane's /v1/pca/issue, decodes the returned PCA_0, and prints the
# salient fields. Documented in spec.md §0.4 acceptance.
#
# Prerequisites:
#   docker compose -f proxilion/docker-compose.yml --project-directory . up -d
#
# The federation-bridge wrapper is deferred (upstream provenance-bridge is
# library-only). Trust Plane's issue handler currently accepts JWTs directly,
# which is sufficient for this smoke test. When the bridge service lands,
# replace MOCK_OKTA / TRUST_PLANE with BRIDGE.

set -euo pipefail

MOCK_OKTA="${MOCK_OKTA_URL:-http://127.0.0.1:9090/default}"
TRUST_PLANE="${TRUST_PLANE_URL:-http://127.0.0.1:8080}"

note() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing dependency: $1" >&2
    exit 1
  }
}

need curl
need jq

note "1. Fetch id_token from mock-okta as alice@demo.local"
ID_TOKEN=$(curl -fsS -X POST "$MOCK_OKTA/token" \
  -d grant_type=client_credentials \
  -d client_id=proxilion-dev \
  -d client_secret=dev-secret \
  -d scope=openid \
  | jq -r '.id_token // .access_token')
# mock-oauth2-server's client_credentials grant returns access_token only (no
# id_token per RFC 6749). The Trust Plane stub validator decodes payload only,
# so the access_token JWT works identically here. When we switch to a real
# bridge with JWKS, we'll switch to a grant that does emit id_token.

if [[ -z "$ID_TOKEN" || "$ID_TOKEN" == "null" ]]; then
  echo "mock-okta did not return an id_token; is the service up on $MOCK_OKTA ?" >&2
  exit 1
fi
echo "id_token (truncated): ${ID_TOKEN:0:40}…"

# Decode payload for visibility.
PAYLOAD=$(printf '%s' "$ID_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null || true)
echo "payload: $PAYLOAD"

note "2. Request PCA_0 from Trust Plane"
# Request a minimal ops set; the Trust Plane will intersect with what its
# validator deems allowed for the credential.
RESPONSE=$(curl -fsS -X POST "$TRUST_PLANE/v1/pca/issue" \
  -H 'content-type: application/json' \
  -d "$(jq -n --arg c "$ID_TOKEN" '{
    credential: $c,
    credential_type: "jwt",
    ops: [
      "drive:read:alice@demo.local",
      "drive:read:engineering"
    ],
    executor_binding: { service: "proxilion-smoke" }
  }')")

echo "$RESPONSE" | jq

note "3. Decode PCA_0"
PCA_B64=$(echo "$RESPONSE" | jq -r .pca)
P_0=$(echo "$RESPONSE" | jq -r .p_0)
HOP=$(echo "$RESPONSE" | jq -r .hop)
OPS=$(echo "$RESPONSE" | jq -r '.ops | join(", ")')

printf 'p_0:   %s\n' "$P_0"
printf 'hop:   %s (must be 0)\n' "$HOP"
printf 'ops:   %s\n' "$OPS"
printf 'pca:   %d bytes (CBOR/COSE, base64-encoded)\n' "$(printf %s "$PCA_B64" | wc -c | tr -d ' ')"

if [[ "$HOP" != "0" ]]; then
  echo "FAIL: hop is not 0" >&2
  exit 2
fi
note "OK — PCA_0 obtained"
