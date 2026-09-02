#!/usr/bin/env bash

# Orbinum Unified Benchmark Runner
#
# Runs runtime-registered pallets through a unified benchmarking workflow.
#
# Usage:
#   ./scripts/benchmarks/run_benchmarks.sh                                  # every pallet
#   ./scripts/benchmarks/run_benchmarks.sh --pallet pallet_ismp_messaging   # just one
#   ./scripts/benchmarks/run_benchmarks.sh --group ismp                     # the ISMP set
#   ./scripts/benchmarks/run_benchmarks.sh --steps 20 --repeat 5            # quicker, less precise
#
# Run this on the reference hardware: a Hetzner CPX62 (16 vCPU / 32 GB), which is where
# every committed weights.rs was measured — check the HOSTNAME line in any of them.
# Weights from different machines are not comparable with each other, and a 16 GB host
# is not enough: the analysis phase of a pallet with several linear components reaches
# ~15 GB and gets OOM-killed there.
#
# Publishable weights need the defaults (50/20). Lowering --steps/--repeat gives numbers
# good for shape, not for committing.
#
# On a smaller host, --db-cache and --no-storage-info reduce the footprint, and
# merge-weights.sh assembles a pallet from per-extrinsic runs. Those are workarounds;
# the right fix is to use the reference machine.

set -euo pipefail

STEPS=50
REPEAT=20
DB_CACHE_ARG=""
HEAP_PAGES=4096
STORAGE_INFO_ARG=""
ONLY_PALLET=""
GROUP=""

usage() {
    # Print the whole header block rather than a hardcoded line range, which silently
    # truncates --help every time the header grows.
    awk 'NR>2 && /^#/ {sub(/^# ?/, ""); print; next} NR>2 {exit}' "$0"
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --steps)      STEPS="$2"; shift 2 ;;
        --repeat)     REPEAT="$2"; shift 2 ;;
        --db-cache)   DB_CACHE_ARG="--db-cache=$2"; shift 2 ;;
        --heap-pages) HEAP_PAGES="$2"; shift 2 ;;
        --pallet)     ONLY_PALLET="$2"; shift 2 ;;
        --group)      GROUP="$2"; shift 2 ;;
        --no-storage-info) STORAGE_INFO_ARG="--no-storage-info"; shift ;;
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
TEMPLATE="./scripts/benchmarks/frame-weight-template.hbs"
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
    #
    # `ismp_grandpa` NEEDS A MANUAL EDIT after regenerating. The CLI always emits a
    # local `pub trait WeightInfo` plus an `impl WeightInfo for ()`, but the runtime has
    # to implement the upstream trait. Fix the generated file by deleting the local trait
    # and the `for ()` impl, then pointing the remaining impl at upstream's:
    #   impl<T: frame_system::Config> ismp_grandpa::weights::WeightInfo for SubstrateWeight<T>
    # Without that, `cargo check -p orbinum-runtime` fails with "the trait bound
    # `SubstrateWeight<Runtime>: ismp_grandpa::WeightInfo` is not satisfied".
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
    #
    # `|| rc=$?` and not `if ! …`: inside an `if` condition, `$?` is the status of the
    # `if` itself, so a SIGKILLed run reads back as 0 and gets reported as a success.
    local rc=0
    "$NODE" benchmark pallet \
        --chain dev \
        --pallet "$pallet" \
        --extrinsic '*' \
        --steps "$STEPS" \
        --repeat "$REPEAT" \
        --wasm-execution=compiled \
        --heap-pages="$HEAP_PAGES" \
        $DB_CACHE_ARG $STORAGE_INFO_ARG \
        --output "$output" \
        --template "$TEMPLATE" || rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "" >&2
        echo "  > FAILED: $pallet (exit $rc)" >&2
        # 137 = 128 + SIGKILL. The OOM killer leaves no other trace, and the generic
        # advice ("check the logs") is useless because the process is simply gone.
        if [[ $rc -eq 137 ]]; then
            echo "  > Exit 137 is SIGKILL — the OOM killer." >&2
            echo "  > Check the host first: this needs the reference machine (CPX62," >&2
            echo "  > 16 vCPU / 32 GB). A 16 GB box is killed during the analysis" >&2
            echo "  > phase, and no flag makes that fit — measured at ~15 GB resident." >&2
            echo "  > On the right host this simply works." >&2
        fi
        return $rc
    fi

    # A killed run can still have written a partial file before dying, and a partial
    # weights file compiles — it just carries wrong numbers. Refuse to call it done.
    if [[ ! -s "$output" ]]; then
        echo "  > FAILED: $pallet produced no output at $output" >&2
        return 1
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
echo "      heap-pages=$HEAP_PAGES ${DB_CACHE_ARG:+$DB_CACHE_ARG }${STORAGE_INFO_ARG}"

failed=()
for entry in "${selected[@]}"; do
    pallet="${entry%%:*}"
    # Keep going after a failure so one OOM-prone pallet does not hide whether the rest
    # would have worked, but remember it: the summary must not claim success.
    run_bench "$pallet" "${entry#*:}" || failed+=("$pallet")
done

echo ""
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "[3/3] FAILED: ${#failed[@]} of ${#selected[@]} benchmark(s) did not complete" >&2
    for pallet in "${failed[@]}"; do
        echo "  - $pallet" >&2
    done
    echo "" >&2
    echo "Weights for the failed pallets are unchanged or incomplete — do not commit" >&2
    echo "them. Re-run each one alone, then verify with 'git diff'." >&2
    echo "------------------------------------------------------" >&2
    exit 1
fi

echo "[3/3] All ${#selected[@]} benchmark(s) completed successfully"
echo "Saved committed weights in frame/*/src/weights.rs and template/runtime/src/weights/"
echo "Saved auxiliary weights in $SCRATCH_DIR"
echo "------------------------------------------------------"
