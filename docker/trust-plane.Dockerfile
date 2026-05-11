# Trust Plane image — builds upstream `provenance-plane` from git.
#
# `cargo install --git` clones the upstream repo, compiles `provenance-plane`,
# and drops the binary in /usr/local/cargo/bin. No COPY of vendored sources.

FROM rust:1.88-bookworm AS builder
RUN cargo install \
    --git https://github.com/clay-good/provenance \
    --branch main \
    --bin provenance-plane \
    --root /out \
    provenance-plane

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/bin/provenance-plane /usr/local/bin/trust-plane
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trust-plane"]
