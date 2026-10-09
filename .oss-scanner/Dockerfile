# Anthropic OSS Scanner build image (https://github.com/anthropics/oss-scanner).
# Built online with the repository as context; the scan then runs offline, so every
# toolchain component, crate and test binary must exist once this file finishes.
FROM rust:1.93.0-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang libclang-dev cmake protobuf-compiler libssl-dev pkg-config git \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives at /src
COPY . /src
WORKDIR /src

# Installs what rust-toolchain.toml pins (wasm32v1-none target, clippy, rustfmt).
RUN rustup toolchain install

RUN cargo fetch --locked

# Same build as CI, plus line tables for usable backtraces. --all-targets compiles the
# test binaries now so they run offline later.
ENV CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
    WASM_BUILD_TYPE=release
RUN cargo build --locked --release --workspace --all-targets

# Smoke-run the unit tests CI runs (`make test-release`); a failure must not abort the image.
RUN cargo test --locked --release --workspace --lib \
    || echo "WARNING: cargo test reported failures"
