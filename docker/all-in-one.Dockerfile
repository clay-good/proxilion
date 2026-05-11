# Proxilion all-in-one: postgres + trust-plane + proxy in a single image.
#
# Use for evaluation, demos, small deployments. For production, prefer the
# separate `docker/proxy.Dockerfile` and `docker/trust-plane.Dockerfile`
# images plus an external postgres (see `docker-compose.yml`).
#
# Build:  docker build -f docker/all-in-one.Dockerfile -t proxilion:dev .
# Run:    docker run -p 8443:8443 -e PROXILION_DEMO=1 proxilion:dev
# Open:   https://localhost:8443/admin/

# --- build proxy ---
FROM rust:1.88-bookworm AS proxy-build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release --locked -p proxy

# --- build trust-plane ---
FROM rust:1.88-bookworm AS trust-plane-build
RUN cargo install \
    --git https://github.com/clay-good/provenance \
    --branch main \
    --bin provenance-plane \
    --root /out \
    provenance-plane

# --- runtime ---
FROM debian:bookworm-slim

ENV POSTGRES_DB=proxilion \
    POSTGRES_USER=proxilion \
    POSTGRES_PASSWORD=proxilion \
    PGDATA=/var/lib/postgresql/data

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl postgresql postgresql-contrib gosu tini \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/postgresql /var/lib/postgresql/data \
 && chown -R postgres:postgres /run/postgresql /var/lib/postgresql

COPY --from=proxy-build       /build/target/release/proxy            /usr/local/bin/proxy
COPY --from=trust-plane-build /out/bin/provenance-plane              /usr/local/bin/trust-plane
COPY docker/entrypoint-all-in-one.sh                                  /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Demo mode + dev TLS cert by default; both are env-overridable.
ENV PROXILION_DEV=1 \
    PROXILION_DEMO=1 \
    PROXILION_BIND_ADDR=0.0.0.0:8443 \
    PROXILION_TLS_CERT=/certs/dev.crt \
    PROXILION_TLS_KEY=/certs/dev.key \
    PROXILION_TRUST_PLANE_URL=http://127.0.0.1:8080 \
    DATABASE_URL=postgres://proxilion:proxilion@127.0.0.1/proxilion \
    TRUST_PLANE_PORT=8080 \
    TRUST_PLANE_NAME=proxilion-all-in-one \
    RUST_LOG=info,proxy=debug

EXPOSE 8443
VOLUME ["/var/lib/postgresql/data", "/certs"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
