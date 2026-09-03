# Multi-stage build for Orbinum Node
# Stage 1: Build the node binary
FROM rust:1.88-bookworm AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    libclang-dev \
    cmake \
    protobuf-compiler \
    libssl-dev \
    pkg-config \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /orbinum

# Copy source code
COPY . .

# Which Hyperbridge deployment the runtime is compiled against. It is a compile-time
# constant, so a testnet image must be built with `hyperbridge-testnet` or it ships
# mainnet's `Polkadot(3367)`: `is_allowed_proxy` compares the whole SCALE variant with
# `==`, so the mismatch rejects every proxied request — at relay time, not at deploy
# time. The release workflow passes this per environment; `scripts/verify-coprocessor.sh`
# checks the result rather than trusting the flag.
ARG CARGO_FEATURES=""

# Build the node in release mode
RUN cargo build --release --package orbinum-node \
    ${CARGO_FEATURES:+--features "$CARGO_FEATURES"}

# Stage 2: Create minimal runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
# curl is needed for inserting session keys via the local RPC (docker exec)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -u 1000 -U -s /bin/sh orbinum && \
    mkdir -p /data && \
    chown -R orbinum:orbinum /data

# Copy binary from builder
COPY --from=builder /orbinum/target/release/orbinum-node /usr/local/bin/orbinum-node

# Copy the runtime WASM built alongside the binary. Bundling it lets the deploy
# job pull the exact runtime the nodes run (docker cp from this image) instead of
# recompiling — guaranteeing the on-chain setCode matches the nodes' binary.
COPY --from=builder \
    /orbinum/target/release/wbuild/orbinum-runtime/orbinum_runtime.compact.compressed.wasm \
    /usr/local/share/orbinum/orbinum_runtime.compact.compressed.wasm

# Set user
USER orbinum

# Expose ports
# 30333: P2P
# 9944: WebSocket RPC
# 9933: HTTP RPC (if enabled)
# 9615: Prometheus metrics
EXPOSE 30333 9944 9933 9615

# Set volume for chain data
VOLUME ["/data"]

# Default command
ENTRYPOINT ["/usr/local/bin/orbinum-node"]
CMD ["--help"]
