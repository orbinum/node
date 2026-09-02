#!/usr/bin/env bash

# Re-run the pallet_ismp_messaging benchmarks against polkadot-sdk PR #13073.
#
# Upstream asked us to verify their fix for the 10^18 `proof_size`
# (paritytech/polkadot-sdk#13066). Their branch cannot be consumed with
# `[patch.crates-io]`: the PR targets `master`, whose in-tree versions
# (frame-benchmarking 28.0.0, benchmarking-cli 32.0.0) do not match the published
# crates we build (frame-benchmarking 49.0.0, benchmarking-cli 58.0.1), and `pallet-ismp` pins `polkadot-sdk =2606.0.0`
# exactly. Patching would drag half of master into a 2606 tree.
#
# So: vendor the two crates we actually build, apply their diff on top, and rebuild.
# This tests their logic against our SDK line rather than theirs.
#
# Run on the reference hardware (Hetzner CPX62, 16 vCPU / 32 GB). A CPX42 gets OOM-
# killed during the analysis phase.
#
# Usage: ./scripts/benchmarks/test-upstream-13073.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PR_DIFF_URL="https://patch-diff.githubusercontent.com/raw/paritytech/polkadot-sdk/pull/13073.diff"
VENDOR_DIR="vendor"
WORK="target/upstream-13073"
mkdir -p "$WORK"

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

say "1/6  fetching the PR diff"
curl -fsSL "$PR_DIFF_URL" -o "$WORK/pr13073.diff"
wc -l < "$WORK/pr13073.diff" | xargs printf '   %s lines\n'

say "2/6  vendoring dependencies"
# --versioned-dirs so the directory names carry versions and the patch targets are
# unambiguous. This writes a .cargo/config fragment we append below.
cargo vendor --versioned-dirs "$VENDOR_DIR" > "$WORK/vendor-config.toml"

# Resolve the directories rather than hardcoding versions: the manifest asks for
# "58.0.0" (i.e. ^58.0.0) and the lockfile picks the newest patch, so the vendored
# directory is frame-benchmarking-cli-58.0.1 today and something else after an update.
find_vendored() {
    local crate="$1" dir
    # -maxdepth 1 so frame-benchmarking-cli does not match frame-benchmarking
    dir=$(find "$VENDOR_DIR" -maxdepth 1 -type d -name "$crate-[0-9]*" | head -1)
    if [[ -z "$dir" ]]; then
        echo "ERROR: no vendored directory for $crate under $VENDOR_DIR/" >&2
        echo "Present:" >&2
        find "$VENDOR_DIR" -maxdepth 1 -type d -name "frame-benchmarking*" | sed 's/^/  /' >&2
        exit 1
    fi
    echo "$dir"
}

FB=$(find_vendored "frame-benchmarking")
CLI=$(find_vendored "frame-benchmarking-cli")
echo "   frame-benchmarking:     ${FB##*/}"
echo "   frame-benchmarking-cli: ${CLI##*/}"

say "3/6  applying the fix to the vendored crates"
# The diff is rooted at the monorepo, so strip the leading components and point each
# hunk at its vendored copy. Context offsets differ by a few lines from master (the PR
# targets master, we build the published 49.0.0/58.0.1), hence -F3.
#
# Split with awk rather than filterdiff: patchutils is not installed on a stock VPS and
# this needs no extra package.
split_hunk() {
    awk -v want="$1" '
        /^diff --git / { f = ($0 ~ want) }
        f
    ' "$WORK/pr13073.diff"
}

apply_one() {
    local want="$1" strip="$2" target_dir="$3" label="$4"
    split_hunk "$want" > "$WORK/$label.patch"
    if [[ ! -s "$WORK/$label.patch" ]]; then
        echo "   ERROR: no hunks matched $label — the PR may have been rebased." >&2
        exit 1
    fi
    if patch -p"$strip" -d "$target_dir" -F3 --no-backup-if-mismatch \
        < "$WORK/$label.patch"
    then
        echo "   applied: $label"
    else
        echo "   FAILED to apply $label against the vendored sources." >&2
        echo "   Re-check the PR; its context no longer matches." >&2
        exit 1
    fi
}

apply_one "substrate/frame/benchmarking/src/analysis.rs" 4 "$FB" "analysis"
apply_one "src/pallet/writer.rs" 5 "$CLI" "writer"

say "4/6  redirecting cargo at the vendored sources"
# This redirect is what makes the build use the patched sources. If it silently fails,
# cargo compiles the unpatched crates from crates.io and the run "passes" while testing
# nothing — so verify the fragment is real before trusting anything downstream.
if ! grep -q 'source.crates-io' "$WORK/vendor-config.toml" 2>/dev/null; then
    echo "ERROR: $WORK/vendor-config.toml has no source replacement stanza." >&2
    echo "cargo vendor printed nothing usable; not continuing, the build would" >&2
    echo "silently use unpatched crates from crates.io." >&2
    exit 1
fi

mkdir -p .cargo
if ! grep -q 'vendored-sources' .cargo/config.toml 2>/dev/null; then
    cp -n .cargo/config.toml "$WORK/config.toml.bak" 2>/dev/null || true
    cat "$WORK/vendor-config.toml" >> .cargo/config.toml
    echo "   appended vendor config (original saved to $WORK/config.toml.bak)"
else
    echo "   vendor config already present"
fi

# Prove the patched source is the one being compiled, not the registry copy.
if ! grep -q 'f64_to_u128_saturating' "$FB/src/analysis.rs"; then
    echo "ERROR: the fix is not present in $FB/src/analysis.rs." >&2
    exit 1
fi

say "5/6  building with runtime-benchmarks"
cargo build --release --features runtime-benchmarks --package orbinum-node

say "6/6  running the dispatch_post benchmark at the settings that broke"
OUT="$WORK/weights-13073.rs"
./target/release/orbinum-node benchmark pallet \
    --chain dev \
    --pallet pallet_ismp_messaging \
    --extrinsic '*' \
    --steps 50 \
    --repeat 20 \
    --wasm-execution=compiled \
    --heap-pages=4096 \
    --default-pov-mode measured \
    --output "$OUT" \
    --template ./scripts/benchmarks/frame-weight-template.hbs

say "result"
echo "Generated: $OUT"
echo
echo "proof_size per extrinsic (second field of from_parts):"
grep -n "Weight::from_parts" "$OUT" | sed 's/^/  /'
echo
BAD=$(grep -oE 'from_parts\([0-9_]+, ([0-9]{10,})\)' "$OUT" | head -5 || true)
if [[ -n "$BAD" ]]; then
    echo "STILL BROKEN — proof_size values with 10+ digits:"
    echo "$BAD" | sed 's/^/  /'
    echo
    echo "Report this back on the PR: the fix did not hold on our tree."
    exit 1
fi
echo "No 10^18 values. dispatch_post's proof_size should sit near 3550 (range 1504-3606)."
echo
echo "To undo: git checkout .cargo/config.toml && rm -rf $VENDOR_DIR"
