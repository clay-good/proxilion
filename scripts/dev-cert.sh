#!/usr/bin/env bash
# Emit a self-signed dev cert at ./certs/dev.crt + ./certs/dev.key if missing.
set -euo pipefail
CERT_DIR="${CERT_DIR:-./certs}"
CRT="$CERT_DIR/dev.crt"
KEY="$CERT_DIR/dev.key"

mkdir -p "$CERT_DIR"
if [[ -f "$CRT" && -f "$KEY" ]]; then
  echo "dev cert already present at $CRT"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$KEY" -out "$CRT"
echo "wrote $CRT and $KEY"
