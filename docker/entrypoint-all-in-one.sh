#!/usr/bin/env bash
# Entrypoint for the all-in-one image: bootstraps postgres, mints a CAT key
# on first boot, starts trust-plane, then exec's the proxy in the foreground.
set -euo pipefail

# --- postgres ---
if [[ ! -s "$PGDATA/PG_VERSION" ]]; then
  echo "[init] initializing postgres data directory at $PGDATA"
  # Use the default 'postgres' superuser for initdb; we'll create the
  # proxilion role + databases below.
  gosu postgres /usr/lib/postgresql/*/bin/initdb -D "$PGDATA" \
       --username=postgres \
       --auth-host=trust --auth-local=trust >/dev/null
fi
PG_LOG="$PGDATA/postgres.log"
gosu postgres /usr/lib/postgresql/*/bin/pg_ctl \
     -D "$PGDATA" -l "$PG_LOG" -o "-h 127.0.0.1 -p 5432" start

# Wait until postgres accepts connections.
for i in $(seq 1 30); do
  if gosu postgres /usr/lib/postgresql/*/bin/pg_isready -h 127.0.0.1 -p 5432 -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# All admin SQL runs as the postgres superuser over TCP/loopback.
PSQL="gosu postgres /usr/lib/postgresql/*/bin/psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -tA"

# Create role + DBs if missing.
eval "$PSQL -c \"SELECT 1 FROM pg_roles WHERE rolname='${POSTGRES_USER}'\"" | grep -q 1 \
  || eval "$PSQL -c \"CREATE ROLE ${POSTGRES_USER} WITH SUPERUSER LOGIN PASSWORD '${POSTGRES_PASSWORD}'\""
eval "$PSQL -c \"SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'\"" | grep -q 1 \
  || eval "$PSQL -c \"CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER}\""
eval "$PSQL -c \"SELECT 1 FROM pg_database WHERE datname='trust_plane'\"" | grep -q 1 \
  || eval "$PSQL -c \"CREATE DATABASE trust_plane OWNER ${POSTGRES_USER}\""

# --- CAT key ---
KEYFILE=/var/lib/postgresql/data/cat_key.hex
if [[ ! -f "$KEYFILE" ]]; then
  openssl rand -hex 32 > "$KEYFILE"
  echo "[init] generated CAT signing key (persisted at $KEYFILE)"
fi
export TRUST_PLANE_CAT_KEY_HEX="$(cat "$KEYFILE")"
export TRUST_PLANE_CAT_KID="${TRUST_PLANE_CAT_KID:-cat-all-in-one-1}"

# --- trust-plane in background ---
echo "[init] starting trust-plane on :${TRUST_PLANE_PORT}"
/usr/local/bin/trust-plane &
TP_PID=$!

# Wait for trust-plane health.
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${TRUST_PLANE_PORT}/v1/federation/info" >/dev/null; then
    break
  fi
  sleep 1
done

# Trap to forward signals to children.
shutdown() {
  echo "[shutdown] stopping trust-plane and postgres"
  kill -TERM "$TP_PID" 2>/dev/null || true
  gosu postgres /usr/lib/postgresql/*/bin/pg_ctl -D "$PGDATA" stop -m fast || true
  exit 0
}
trap shutdown TERM INT

# --- proxy (foreground) ---
mkdir -p /certs
echo "[init] starting proxy on :8443"
exec /usr/local/bin/proxy
