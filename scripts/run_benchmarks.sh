#!/bin/bash

# Orbinum Benchmark Runner
# Usage: ./scripts/run_benchmarks.sh

set -e

echo "------------------------------------------------------"
echo "   Orbinum Network - Benchmark Runner"
echo "------------------------------------------------------"

# 1. Build Node
echo "[1/3] Building node with 'runtime-benchmarks' feature..."
cargo build --release --features runtime-benchmarks

# Configuration
NODE="./target/release/orbinum-node"
RUNTIME_WASM="./target/release/wbuild/orbinum-runtime/orbinum_runtime.compact.compressed.wasm"
STEPS=50
REPEAT=20
TEMPLATE="./scripts/frame-weight-template.hbs"

# Check if node exists
if [ ! -f "$NODE" ]; then
    echo "Error: Node binary not found at $NODE"
    exit 1
fi

# Check if runtime WASM exists
if [ ! -f "$RUNTIME_WASM" ]; then
    echo "Error: Runtime WASM not found at $RUNTIME_WASM"
    exit 1
fi

# Function
run_bench() {
    PALLET=$1
    OUTPUT_FILE=$2
    
    echo ""
    echo "[Benchmarking] Pallet: $PALLET"
    echo "  > Output: $OUTPUT_FILE"
    
    $NODE benchmark pallet \
        --runtime "$RUNTIME_WASM" \
        --genesis-builder=runtime \
        --pallet "$PALLET" \
        --extrinsic '*' \
        --steps $STEPS \
        --repeat $REPEAT \
        --output "$OUTPUT_FILE" \
        --template "$TEMPLATE" \
        --wasm-execution=compiled \
        --heap-pages=4096

    echo "  > Done."
}

echo ""
echo "[2/3] Running Benchmarks..."

# --- 1. Zk Verifier ---
run_bench "pallet_zk_verifier" "./frame/zk-verifier/src/weights.rs"

# --- 2. Shielded Pool ---
run_bench "pallet_shielded_pool" "./frame/shielded-pool/src/weights.rs"

# --- 3. EVM Precompiles (Optional example) ---
# run_bench "pallet_evm_precompile_curve25519" "./frame/evm/precompile/curve25519/src/weights.rs"

echo ""
echo "------------------------------------------------------"
echo "[3/3] All benchmarks completed successfully!"
echo "------------------------------------------------------"
