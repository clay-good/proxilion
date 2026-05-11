# Proxilion proxy image.
#
# Build context: the repo root (`proxilion/`). Upstream `pic-protocol` and
# `provenance-*` are fetched by Cargo from git per Cargo.toml's `[workspace.dependencies]`.

FROM rust:1.88-bookworm AS builder
WORKDIR /build
# Layer cache: copy manifests first, then sources.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release --locked -p proxy

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/proxy /usr/local/bin/proxy
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/proxy"]
