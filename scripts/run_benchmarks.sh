#!/usr/bin/env bash

# Orbinum Unified Benchmark Runner
#
# Runs runtime-registered pallets through a unified benchmarking workflow.
#
# Usage:
#   ./scripts/run_benchmarks.sh                                  # every pallet
#   ./scripts/run_benchmarks.sh --pallet pallet_ismp_messaging   # just one
#   ./scripts/run_benchmarks.sh --group ismp                     # the ISMP set
#   ./scripts/run_benchmarks.sh --steps 20 --repeat 5            # quicker, less precise
#   ./scripts/run_benchmarks.sh --db-cache 256 --heap-pages 2048 # lower memory ceiling
#
# Publishable weights need the defaults (50/20) on a machine with stable timing — a
# dedicated VPS, not a laptop. The knobs exist so a run can be rehearsed locally without
# being killed; numbers from a reduced run are for shape, not for committing.
#
# On memory: the runner holds every batch in memory until it writes the file, on top of
# the db cache (1 GiB by default) and the Wasm heap. Pallets doing real cryptography —
# zk-verifier and shielded-pool run Groth16 over BN254 — are the ones that get reaped by
# the OOM killer first, and the failure looks like `Killed` with no other explanation.
# If that happens, lower --db-cache before anything else, and benchmark one pallet at a
# time so a kill does not discard the work already done.

set -euo pipefail

STEPS=50
REPEAT=20
DB_CACHE=1024
HEAP_PAGES=4096
ONLY_PALLET=""
GROUP=""

usage() {
    sed -n '3,25p' "$0" | sed 's|^# \{0,1\}||'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --steps)      STEPS="$2"; shift 2 ;;
        --repeat)     REPEAT="$2"; shift 2 ;;
        --db-cache)   DB_CACHE="$2"; shift 2 ;;
        --heap-pages) HEAP_PAGES="$2"; shift 2 ;;
        --pallet)     ONLY_PALLET="$2"; shift 2 ;;
        --group)      GROUP="$2"; shift 2 ;;
        -h|--help)    usage 0 ;;
        *)
            echo "Unknown option: $1" >&2
            usage 1
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

# Every pallet registered in the runtime's `define_benchmarks!`, paired with where its
# generated weights belong. Keep this list in sync with `template/runtime/src/lib.rs`:
# a pallet named here but absent there fails with "pallet not found", and one added
# there but missing here silently never gets benchmarked.
#
# `pallet_ismp` is deliberately absent: the 2606 line dropped its benchmarking module,
# so the runtime does not register it and there is no weights file to generate.
PALLETS=(
    # pallet:output:group
    "pallet_zk_verifier:./frame/zk-verifier/src/weights.rs:core"
    "pallet_shielded_pool:./frame/shielded-pool/src/weights.rs:core"
    "pallet_relayer:./frame/relayer/src/weights.rs:core"
    "pallet_validator_set:./frame/validator-set/src/weights.rs:core"
    # ISMP crates we do not own: the WeightInfo trait belongs to the upstream crate, so
    # the generated impl lives runtime-side rather than in the pallet.
    "pallet_ismp_messaging:./frame/ismp-messaging/src/weights.rs:ismp"
    "ismp_grandpa:./template/runtime/src/weights/ismp_grandpa.rs:ismp"
    # Runtime pallets with no versioned weights destination in this repo.
    "pallet_balances:$SCRATCH_DIR/pallet-balances-weights.rs:aux"
    "pallet_timestamp:$SCRATCH_DIR/pallet-timestamp-weights.rs:aux"
    "pallet_sudo:$SCRATCH_DIR/pallet-sudo-weights.rs:aux"
    "pallet_evm:$SCRATCH_DIR/pallet-evm-weights.rs:aux"
    "pallet_evm_precompile_curve25519:$SCRATCH_DIR/pallet-evm-precompile-curve25519-weights.rs:aux"
    "pallet_evm_precompile_sha3fips:$SCRATCH_DIR/pallet-evm-precompile-sha3fips-weights.rs:aux"
)

run_bench() {
    local pallet="$1"
    local output="$2"

    echo ""
    echo "[Benchmarking] Pallet: $pallet"
    echo "  > Output: $output"

    mkdir -p "$(dirname "$output")"

    # `--execution` is gone: it is accepted but documented as having no effect, and
    # `--wasm-execution=compiled` is what actually selects the executor.
    if ! "$NODE" benchmark pallet \
        --chain dev \
        --pallet "$pallet" \
        --extrinsic '*' \
        --steps "$STEPS" \
        --repeat "$REPEAT" \
        --wasm-execution=compiled \
        --heap-pages="$HEAP_PAGES" \
        --db-cache="$DB_CACHE" \
        --output "$output" \
        --template "$TEMPLATE"
    then
        local rc=$?
        echo "" >&2
        echo "  > FAILED: $pallet (exit $rc)" >&2
        # 137 = 128 + SIGKILL. The OOM killer leaves no other trace, and the generic
        # advice ("check the logs") is useless because the process is simply gone.
        if [[ $rc -eq 137 ]]; then
            echo "  > Exit 137 is SIGKILL — almost always the OOM killer." >&2
            echo "  > Retry that pallet alone with a smaller footprint, e.g.:" >&2
            echo "  >   $0 --pallet $pallet --db-cache 256 --steps 20 --repeat 5" >&2
        fi
        return $rc
    fi

    echo "  > Done."
}

selected=()
for entry in "${PALLETS[@]}"; do
    [[ "$entry" =~ ^[[:space:]]*# ]] && continue
    IFS=':' read -r pallet output group <<< "$entry"
    if [[ -n "$ONLY_PALLET" && "$pallet" != "$ONLY_PALLET" ]]; then continue; fi
    if [[ -n "$GROUP" && "$group" != "$GROUP" ]]; then continue; fi
    selected+=("$pallet:$output")
done

if [[ ${#selected[@]} -eq 0 ]]; then
    echo "Error: no pallet matched the filter (--pallet '$ONLY_PALLET' --group '$GROUP')." >&2
    echo "Known pallets:" >&2
    for entry in "${PALLETS[@]}"; do
        [[ "$entry" =~ ^[[:space:]]*# ]] && continue
        IFS=':' read -r pallet _ group <<< "$entry"
        printf '  %-40s (group: %s)\n' "$pallet" "$group" >&2
    done
    exit 1
fi

echo ""
echo "[1/3] Building node with features: ${FEATURES}"
cargo build --release --features "${FEATURES}"

if [[ ! -f "$NODE" ]]; then
    echo "Error: node binary not found at $NODE" >&2
    exit 1
fi

mkdir -p "$SCRATCH_DIR"

echo ""
echo "[2/3] Running ${#selected[@]} benchmark(s) — steps=$STEPS repeat=$REPEAT"
echo "      heap-pages=$HEAP_PAGES db-cache=${DB_CACHE}MiB"

for entry in "${selected[@]}"; do
    run_bench "${entry%%:*}" "${entry#*:}"
done

echo ""
echo "[3/3] All benchmarks completed successfully"
echo "Saved committed weights in frame/*/src/weights.rs and template/runtime/src/weights/"
echo "Saved auxiliary weights in $SCRATCH_DIR"
echo "------------------------------------------------------"
