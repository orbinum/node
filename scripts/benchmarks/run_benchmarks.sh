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
#   ./scripts/benchmarks/run_benchmarks.sh --storage-info                   # restore the screen dump
#
# Publishable weights need the defaults (50/20) on a machine with stable timing — a
# dedicated VPS, not a laptop. Lowering --steps/--repeat gives numbers good for shape,
# not for committing.
#
# On memory: `--no-storage-info` is passed by default, and it is not cosmetic. Without
# it the runner spends most of its wall time in a post-processing phase that clones a
# `BenchmarkResult` per storage prefix per run (upstream `pallet/command.rs`, the
# `storage_per_prefix` map), swinging between megabytes and ~5 GB. Measured on this
# pallet, 16 GiB and no swap: the default run peaked at 4.7 GB and was OOM-killed after
# 672s, while `--no-storage-info` finished in 196s. The peak is similar either way —
# what changes is how long the process sits in the danger zone.
#
# The flag only suppresses the *screen* dump. Upstream documents it as "independent of
# the storage info appearing in the output file", the weights are recomputed by the
# writer afterwards, and the generated file is byte-comparable. Pass --storage-info when
# you actually need to read the per-key table.
#
# Still getting killed? Check swap first — a host with 0B swap (the Hetzner default) has
# nowhere to put a transient spike and the kernel reaps the process instantly:
#
#   free -h                                             # Swap: 0B is the problem
#   sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
#   sudo mkswap /swapfile && sudo swapon /swapfile       # not persisted across reboot
#
# Then lower --db-cache, then benchmark one pallet at a time so a kill does not discard
# the work already done.
#
# If a single pallet still cannot fit, measure one extrinsic per process and stitch the
# results together — `--extrinsic <name>` alone emits a file whose trait declares only
# that function, which does not compile against the pallet:
#
#   for e in dispatch_post accept_source …; do
#     ./target/release/orbinum-node benchmark pallet --chain dev \
#       --pallet <pallet> --extrinsic "$e" --steps 50 --repeat 20 \
#       --wasm-execution=compiled --no-storage-info \
#       --output "/tmp/parts/$e.rs" --template ./scripts/benchmarks/frame-weight-template.hbs
#   done
#   ./scripts/benchmarks/merge-weights.sh <destination>.rs /tmp/parts/*.rs

set -euo pipefail

STEPS=50
REPEAT=20
DB_CACHE=1024
HEAP_PAGES=4096
# On by default: see the note above — it is what keeps the run out of the OOM window.
STORAGE_INFO_ARG="--no-storage-info"
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
        --db-cache)   DB_CACHE="$2"; shift 2 ;;
        --heap-pages) HEAP_PAGES="$2"; shift 2 ;;
        --pallet)     ONLY_PALLET="$2"; shift 2 ;;
        --group)      GROUP="$2"; shift 2 ;;
        --storage-info) STORAGE_INFO_ARG=""; shift ;;
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
        --db-cache="$DB_CACHE" \
        $STORAGE_INFO_ARG \
        --output "$output" \
        --template "$TEMPLATE" || rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "" >&2
        echo "  > FAILED: $pallet (exit $rc)" >&2
        # 137 = 128 + SIGKILL. The OOM killer leaves no other trace, and the generic
        # advice ("check the logs") is useless because the process is simply gone.
        if [[ $rc -eq 137 ]]; then
            echo "  > Exit 137 is SIGKILL — almost always the OOM killer." >&2
            echo "  > Check for swap first: 'free -h'. A host with 0B swap dies on any" >&2
            echo "  > transient spike, and this phase spikes by gigabytes." >&2
            echo "  > Then retry the pallet alone, with a smaller db cache:" >&2
            echo "  >   $0 --pallet $pallet --db-cache 256" >&2
            echo "  > Keep --steps/--repeat at their defaults for weights you intend" >&2
            echo "  > to commit; lower them only to rehearse the run." >&2
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
echo "      heap-pages=$HEAP_PAGES db-cache=${DB_CACHE}MiB"

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
