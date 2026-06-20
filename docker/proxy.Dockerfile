# Proxilion proxy image (production-readiness.md PR-11).
#
# Multi-stage build → minimal, non-root, distroless runtime suitable for a
# read-only root filesystem. Build context is the repo root (`proxilion/`);
# the upstream `provenance-*` git dependency is fetched by Cargo per
# Cargo.toml's `[workspace.dependencies]`.
#
# Build (single-arch, local):
#   docker build -f docker/proxy.Dockerfile -t proxilion-proxy:dev .
# Multi-arch publish is done by the release workflow (buildx → GHCR), which
# also Trivy-scans the result and emits the digest to pin in Helm values.

# ── Builder ──────────────────────────────────────────────────────────────
# Pinned to the toolchain we test against (>= MSRV 1.85). cargo build with
# --locked so the image reproduces from Cargo.lock exactly.
FROM rust:1.88-bookworm AS builder
WORKDIR /build
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
# Manifests first for layer caching, then sources.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release --locked -p proxy \
 && strip target/release/proxy

# ── Runtime ──────────────────────────────────────────────────────────────
# distroless/cc: glibc + libgcc + CA certificates, no shell / package manager
# / setuid binaries. `:nonroot` runs as uid 65532. Pair with the Helm chart's
# readOnlyRootFilesystem + a writable /tmp emptyDir. Pin by digest in
# production (the release flow records the multi-arch digest).
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/proxy /usr/local/bin/proxy
# Already nonroot via the base tag; restate for clarity and standalone runs.
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/proxy"]
