# Proxilion MCP Security Gateway - Multi-Stage Docker Build
#
# 100% Open Source, Docker-First Architecture
# No Cloudflare dependencies - runs anywhere
#
# Build: docker build -t proxilion/gateway:latest .
# Run:   docker compose up -d

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM rust:1.83-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build in release mode with only Redis store (no Cloudflare)
RUN cargo build --release --package gateway

# ============================================================================
# Stage 2: Runtime Environment
# ============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 proxilion

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/proxilion-gateway /usr/local/bin/proxilion-gateway

# Change ownership
RUN chown -R proxilion:proxilion /app

# Switch to non-root user
USER proxilion

# Expose ports
EXPOSE 8787 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8787/health || exit 1

# Set default environment variables
ENV MODE=monitor \
    RUST_LOG=info \
    LISTEN_ADDR=0.0.0.0:8787 \
    SESSION_STORE=redis \
    REDIS_URL=redis://redis:6379

# Run the gateway
CMD ["proxilion-gateway"]
