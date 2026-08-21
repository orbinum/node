#!/usr/bin/env bash

# Orbinum Unified Benchmark Runner
#
# Runs all runtime-registered pallets through a unified benchmarking workflow.
#
# Usage:
#   ./scripts/run_benchmarks.sh
#   ./scripts/run_benchmarks.sh --steps 50 --repeat 20

set -euo pipefail

STEPS=50
REPEAT=20

while [[ $# -gt 0 ]]; do
    case "$1" in
        --steps)
            STEPS="$2"
            shift 2
            ;;
        --repeat)
            REPEAT="$2"
            shift 2
            ;;
        *)
            echo "Opción desconocida: $1"
            exit 1
            ;;
    esac
done

echo "------------------------------------------------------"
echo "   Orbinum Network - Unified Benchmark Runner"
echo "------------------------------------------------------"

# skip-proof-verification lets the runner measure weights with dummy proofs; it is
# kept out of release builds (an integrity_test panics if it reaches a live chain).
FEATURES="runtime-benchmarks,skip-proof-verification,poseidon-native"
NODE="./target/release/orbinum-node"
TEMPLATE="./scripts/frame-weight-template.hbs"
SCRATCH_DIR="./target/benchmark-weights"

echo "[1/3] Building node with features: ${FEATURES}"
cargo build --release --features "${FEATURES}"

if [[ ! -f "$NODE" ]]; then
    echo "Error: node binary not found at $NODE"
    exit 1
fi

mkdir -p "$SCRATCH_DIR"
mkdir -p ./frame/zk-verifier/src ./frame/shielded-pool/src ./frame/relayer/src

run_bench() {
    local pallet="$1"
    local output="$2"

    echo ""
    echo "[Benchmarking] Pallet: $pallet"
    echo "  > Output: $output"

    "$NODE" benchmark pallet \
        --chain dev \
        --pallet "$pallet" \
        --extrinsic '*' \
        --steps "$STEPS" \
        --repeat "$REPEAT" \
        --execution=wasm \
        --wasm-execution=compiled \
        --heap-pages=4096 \
        --output "$output" \
        --template "$TEMPLATE"

    echo "  > Done."
}

echo ""
echo "[2/3] Running benchmarks for full runtime set..."

# Pallets con archivo de weights propio en el repo
run_bench "pallet_zk_verifier" "./frame/zk-verifier/src/weights.rs"
run_bench "pallet_shielded_pool" "./frame/shielded-pool/src/weights.rs"
run_bench "pallet_relayer" "./frame/relayer/src/weights.rs"
run_bench "pallet_validator_set" "./frame/validator-set/src/weights.rs"

# Pallets benchmarkeables del runtime sin destino de weights versionado en este repo
run_bench "pallet_balances" "$SCRATCH_DIR/pallet-balances-weights.rs"
run_bench "pallet_timestamp" "$SCRATCH_DIR/pallet-timestamp-weights.rs"
run_bench "pallet_sudo" "$SCRATCH_DIR/pallet-sudo-weights.rs"
run_bench "pallet_evm" "$SCRATCH_DIR/pallet-evm-weights.rs"
run_bench "pallet_evm_precompile_curve25519" "$SCRATCH_DIR/pallet-evm-precompile-curve25519-weights.rs"
run_bench "pallet_evm_precompile_sha3fips" "$SCRATCH_DIR/pallet-evm-precompile-sha3fips-weights.rs"

echo ""
echo "[3/3] All benchmarks completed successfully"
echo "Saved committed weights in frame/*/src/weights.rs"
echo "Saved auxiliary weights in $SCRATCH_DIR"
echo "------------------------------------------------------"
