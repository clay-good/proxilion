#!/usr/bin/env bash
# Scenario 1 — Inspect a PIC chain.
#
# Issues a PCA_0 against the Trust Plane and pretty-prints the fields the
# audit story rests on: p_0 (the human principal), ops (capability set),
# hop (chain depth), signature.

source "$(dirname "$0")/_lib.sh"
require curl jq docker uuidgen xxd openssl

hdr "Mint PCA_0 for alice@demo.local with engineering-shaped ops"
mint_pca0 '[
  "drive:read:alice@demo.local",
  "drive:read:engineering",
  "gmail:send:alice@demo.local"
]'

say "PCA_0 issued:"
printf '\n'
say "  p_0:       \033[1m$PCA0_P0\033[0m"
say "  hop:       0  ← root of the chain"
say "  ops:       $(jq -r 'join(", ")' <<<"$PCA0_OPS_JSON")"
say "  cache_id:  $PCA0_ID"
say "  cbor_len:  $(printf %s "$PCA0_B64" | base64 -d | wc -c | tr -d ' ') bytes (COSE_Sign1)"
printf '\n'

hdr "Verify via Proxilion's PCA verifier"
$CURL "$PROXY/api/v1/pca/$PCA0_ID/verify" | jq

green "Chain root established. p_0 will be carried unchanged on every successor."
