# ==============================================================================
# Velcrux Multi-Stage Production Dockerfile (docs/OPERATIONS.md §9)
# ==============================================================================

# --- Stage 1: Build Binaries ---
FROM rust:1.80-slim-bookworm AS builder

WORKDIR /usr/src/velcrux

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests and source tree
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

# Build release binaries for client and server
RUN cargo build --release -p velcrux-server -p velcrux-client

# --- Stage 2: Runtime Image ---
FROM debian:bookworm-slim

# Install runtime utilities (curl for healthcheck, ca-certificates)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged velcrux user and group
RUN groupadd -g 10001 velcrux && \
    useradd -u 10001 -g velcrux -m -s /bin/bash velcrux

# Create directory layout per OPERATIONS.md §2
RUN mkdir -p /etc/velcrux \
             /var/lib/velcrux \
             /data/velcrux/files/.velcrux-staging \
             /data/velcrux/chunks \
    && chown -R velcrux:velcrux /etc/velcrux /var/lib/velcrux /data/velcrux

# Copy compiled binaries from builder stage
COPY --from=builder /usr/src/velcrux/target/release/velcruxd /usr/local/bin/velcruxd
COPY --from=builder /usr/src/velcrux/target/release/velcrux /usr/local/bin/velcrux

# Copy default configurations and entrypoint
COPY packaging/etc/velcrux/server.toml /etc/velcrux/server.toml
COPY packaging/etc/velcrux/grants.toml /etc/velcrux/grants.toml
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh && \
    chown -R velcrux:velcrux /etc/velcrux

# Expose QUIC data/control port (UDP) and Prometheus telemetry port (TCP)
EXPOSE 7443/udp
EXPOSE 9443/tcp

# Healthcheck targeting the Prometheus /metrics endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:9443/metrics || exit 1

# Run as unprivileged user
USER velcrux:velcrux
WORKDIR /var/lib/velcrux

VOLUME ["/data/velcrux", "/var/lib/velcrux", "/etc/velcrux"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/etc/velcrux/server.toml"]
