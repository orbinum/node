# syntax=docker/dockerfile:1
# Orbinum node image. Three stages:
#   builder   — compiles binary + runtime WASM from source
#   artifacts — the two build outputs, flat, nothing else
#   (final)   — minimal runtime image
#
# CI compiles once: the release workflow exports `artifacts` to disk
# (`--target artifacts --output type=local`), verifies and publishes those files, then
# builds the final image with `--build-context artifacts=./dist` so the image carries
# byte-identical outputs without compiling again. A plain `docker build .` still
# compiles from source.

# Exact patch pinned to match rust-toolchain.toml, so rustup finds the toolchain
# already installed instead of downloading it on every build.
FROM rust:1.93.0-bookworm AS builder

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

WORKDIR /orbinum
COPY . .

# Which Hyperbridge deployment the runtime is compiled against. It is a compile-time
# constant, so a testnet image must be built with `hyperbridge-testnet` or it ships
# mainnet's `Polkadot(3367)`: `is_allowed_proxy` compares the whole SCALE variant with
# `==`, so the mismatch rejects every proxied request — at relay time, not at deploy
# time. The release workflow passes this per environment; `scripts/verify-coprocessor.sh`
# checks the result rather than trusting the flag.
ARG CARGO_FEATURES=""
ENV WASM_BUILD_TYPE=release

# rustup picks the toolchain from rust-toolchain.toml (channel, wasm32v1-none target).
RUN cargo build --release --package orbinum-node \
    ${CARGO_FEATURES:+--features "$CARGO_FEATURES"} \
    && mkdir /out \
    && cp target/release/orbinum-node \
          target/release/wbuild/orbinum-runtime/orbinum_runtime.compact.compressed.wasm \
          /out/

FROM scratch AS artifacts
COPY --from=builder /out/ /

FROM debian:bookworm-slim

# curl is needed for inserting session keys via the local RPC (docker exec)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -U -s /bin/sh orbinum && \
    mkdir -p /data && \
    chown -R orbinum:orbinum /data

COPY --from=artifacts /orbinum-node /usr/local/bin/orbinum-node

# The runtime WASM ships inside the image so `deploy-runtime` can docker-cp the exact
# runtime the nodes run for the on-chain setCode.
COPY --from=artifacts /orbinum_runtime.compact.compressed.wasm \
    /usr/local/share/orbinum/orbinum_runtime.compact.compressed.wasm

USER orbinum

# 30333: P2P · 9944: WebSocket RPC · 9933: HTTP RPC · 9615: Prometheus
EXPOSE 30333 9944 9933 9615

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/orbinum-node"]
CMD ["--help"]
