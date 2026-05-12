# Shared helpers for demo scripts. Source this; don't run directly.

set -euo pipefail

PROXY="${PROXY:-https://127.0.0.1:8443}"
TP="${TRUST_PLANE_URL:-http://127.0.0.1:8080}"
MOCK_OKTA="${MOCK_OKTA_URL:-http://127.0.0.1:9090/default}"
PG_CONTAINER="${PG_CONTAINER:-proxilion-dev-postgres-1}"

CURL="curl -sk --max-time 10"

green() { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
red()   { printf '\033[1;31m✗\033[0m %s\n' "$*"; }
say()   { printf '  %b\n' "$*"; }
hdr()   { printf '\033[1;33m  ── %s ──\033[0m\n' "$*"; }

pg() {
  docker exec -i "$PG_CONTAINER" psql -U proxilion -d proxilion -tA -c "$@"
}

require() {
  for d in "$@"; do
    command -v "$d" >/dev/null || { red "missing dependency: $d"; exit 1; }
  done
}

# Mint a real PCA_0 from the Trust Plane via the mock-okta JWT flow.
# Sets globals PCA0_B64, PCA0_P0, PCA0_OPS_JSON, PCA0_ID (cached row id).
mint_pca0() {
  local ops_args="$1"  # JSON array string, e.g. '["drive:read:alice@demo.local"]'
  local id_token
  id_token=$(curl -fsS -X POST "$MOCK_OKTA/token" \
    -d grant_type=client_credentials -d client_id=proxilion-dev \
    -d client_secret=dev-secret -d scope=openid \
    | jq -r '.id_token // .access_token')

  local resp
  resp=$(curl -fsS -X POST "$TP/v1/pca/issue" \
    -H 'content-type: application/json' \
    -d "$(jq -n --arg c "$id_token" --argjson ops "$ops_args" '{
          credential: $c,
          credential_type: "jwt",
          ops: $ops,
          executor_binding: {service:"proxilion-demo"}
        }')")
  PCA0_B64=$(jq -r .pca <<<"$resp")
  PCA0_P0=$(jq -r .p_0 <<<"$resp")
  PCA0_OPS_JSON=$(jq -c .ops <<<"$resp")
  PCA0_CBOR_HEX=$(printf %s "$PCA0_B64" | base64 -d | xxd -p | tr -d '\n')
  PCA0_ID=$(uuidgen | tr 'A-Z' 'a-z')
  pg "INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, predecessor_id, signature)
      VALUES ('$PCA0_ID', '\\x$PCA0_CBOR_HEX'::bytea, '$PCA0_P0',
              '$PCA0_OPS_JSON'::jsonb, 0, NULL, '\\x'::bytea);" >/dev/null
}
