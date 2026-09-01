#!/usr/bin/env bash

# Merge per-extrinsic weight files into one complete weights.rs.
#
# Usage:
#   ./scripts/benchmarks/merge-weights.sh <output.rs> <part1.rs> <part2.rs> ...
#   ./scripts/benchmarks/merge-weights.sh --allow-partial <output.rs> <part.rs>
#
# Why this exists: `benchmark pallet --extrinsic <one>` emits a file whose `WeightInfo`
# trait declares only that one function, so it does not satisfy the pallet's real trait.
# Benchmarking one extrinsic per process is the last resort when a host cannot hold a
# whole-pallet run in memory (see run_benchmarks.sh on the OOM window) — this stitches
# the pieces back into something that compiles.
#
# Prefer a single whole-pallet run. Reach for this only when that keeps getting killed
# and adding swap is not an option: the parts must come from the same machine, the same
# binary and the same --steps/--repeat, or the numbers are not comparable with each other.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    sed -n '3,17p' "$0" | sed 's|^# \{0,1\}||'
    exit 1
fi

ALLOW_PARTIAL=0
if [[ "${1:-}" == "--allow-partial" ]]; then ALLOW_PARTIAL=1; shift; fi

OUTPUT="$1"; shift
PARTS=("$@")

for part in "${PARTS[@]}"; do
    [[ -s "$part" ]] || { echo "Error: missing or empty part: $part" >&2; exit 1; }
done

# Refuse to overwrite a complete weights file with fewer functions than it already has.
# A partial merge compiles only if the trait happens to match, and when it does not the
# error points at the runtime rather than here — but the real damage is the silent case:
# a file that compiles while missing an extrinsic's real cost. If one part was killed,
# the merge must fail, not quietly narrow the file.
if [[ -s "$OUTPUT" && $ALLOW_PARTIAL -eq 0 ]]; then
    existing=$(grep -cE "^[[:space:]]+fn [a-z_]+\(.*-> Weight;" "$OUTPUT" || true)
    incoming=${#PARTS[@]}
    if [[ "$existing" -gt 0 && "$incoming" -lt "$existing" ]]; then
        echo "Error: $OUTPUT already declares $existing weight functions, but only" >&2
        echo "       $incoming part(s) were given. Merging would drop the rest." >&2
        echo "       Re-run the missing extrinsics, or pass --allow-partial if you" >&2
        echo "       really mean to shrink the file." >&2
        exit 1
    fi
fi

# Guard against silently mixing runs that are not comparable. The header records the
# machine and the step/repeat counts, so a mismatch there means the numbers came from
# different conditions and must not share one file.
ref_meta=$(grep -hE "^//! (DATE|HOSTNAME)" "${PARTS[0]}" | sed 's/DATE: [^,]*, //')
for part in "${PARTS[@]:1}"; do
    if [[ "$(grep -hE "^//! (DATE|HOSTNAME)" "$part" | sed 's/DATE: [^,]*, //')" != "$ref_meta" ]]; then
        echo "Error: $part was generated under different conditions than ${PARTS[0]}." >&2
        echo "       Re-run every part on the same host with the same flags." >&2
        exit 1
    fi
done

# Each part has the same four sections; we take the preamble from the first and then
# concatenate the function bodies from every part into each of the three impl blocks.
extract_bodies() {
    # Prints the `fn ...` items inside the block that starts at $2 in file $1.
    awk -v start="$2" '
        NR > start && /^}/ { exit }
        NR > start { print }
    ' "$1"
}

first="${PARTS[0]}"
trait_line=$(grep -n "^pub trait WeightInfo {" "$first" | cut -d: -f1)
subst_line=$(grep -n "^impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {" "$first" | cut -d: -f1)
unit_line=$(grep -n "^impl WeightInfo for () {" "$first" | cut -d: -f1)

{
    # Preamble, up to and including the trait opening.
    sed -n "1,${trait_line}p" "$first"
    for part in "${PARTS[@]}"; do
        line=$(grep -n "^pub trait WeightInfo {" "$part" | cut -d: -f1)
        extract_bodies "$part" "$line"
    done
    echo "}"
    echo ""

    # Whatever sits between the trait's closing brace and the SubstrateWeight impl (the
    # struct declaration and its doc comment). The trait's length varies with how many
    # functions the part declares, so find its `}` instead of assuming an offset.
    trait_end=$(awk -v s="$trait_line" 'NR > s && /^}/ { print NR; exit }' "$first")
    sed -n "$((trait_end + 1)),$((subst_line - 1))p" "$first"
    echo "impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {"
    for part in "${PARTS[@]}"; do
        line=$(grep -n "^impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {" "$part" | cut -d: -f1)
        extract_bodies "$part" "$line"
    done
    echo "}"
    echo ""

    # `impl WeightInfo for ()` — the fallback used by mocks and by runtimes that have
    # not wired SubstrateWeight yet.
    echo "// For backwards compatibility and tests."
    echo "impl WeightInfo for () {"
    for part in "${PARTS[@]}"; do
        line=$(grep -n "^impl WeightInfo for () {" "$part" | cut -d: -f1)
        extract_bodies "$part" "$line"
    done
    echo "}"
} > "$OUTPUT"

fns=$(grep -cE "^\s+fn [a-z_]+" "$OUTPUT" || true)
echo "Merged ${#PARTS[@]} part(s) into $OUTPUT ($fns fn entries across 3 sections)."
echo "Now verify it compiles: cargo test -p <the pallet>"
