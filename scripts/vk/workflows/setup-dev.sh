#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# scripts/vk/workflows/setup-dev.sh
# DEV setup for on-chain VKs (main entrypoint for developers)
#
# Registers + activates ONLY these 3 circuits:
#   1 transfer
#   2 unshield
#   6 value_proof
#
# VK artifacts are resolved from the @orbinum/circuits npm package via unpkg:
#   1. Fetches manifest.json to determine the latest package_version
#   2. Pins all artifact URLs to that exact version
#   3. Downloads the JSON VK if not already present in ./artifacts/
#   4. Converts each JSON VK to arkworks compressed binary format before
#      registering it on-chain (the Rust verifier expects binary, not JSON).
#
# USAGE:
#   bash scripts/vk/workflows/setup-dev.sh [rpc_ws] [sudo_seed] [version] [npm_package]
#
# EXAMPLES:
#   bash scripts/vk/workflows/setup-dev.sh
#   bash scripts/vk/workflows/setup-dev.sh ws://127.0.0.1:9944 "//Alice" 1
#   bash scripts/vk/workflows/setup-dev.sh ws://10.0.0.5:9944 "<mnemonic>" 2 "@orbinum/circuits@0.4.4"
# ============================================================================

RPC_WS="${1:-ws://127.0.0.1:9944}"
SUDO_SEED="${2:-//Alice}"
VERSION="${3:-1}"
NPM_PACKAGE="${4:-@orbinum/circuits}"

UNPKG_BASE="https://unpkg.com"
MANIFEST_URL="$UNPKG_BASE/$NPM_PACKAGE/manifest.json"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VK_REGISTRY_SCRIPT="$SCRIPT_DIR/../lib/registry.sh"
ARTIFACTS_DIR="$NODE_DIR/artifacts"
CONVERT_VK_BIN="$NODE_DIR/../groth16-proofs/target/release/convert-vk"

err() {
  echo "[ERROR] $*" >&2
  exit 1
}

log() {
  echo "[$(date '+%H:%M:%S')] $*" >&2
}

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v jq   >/dev/null 2>&1 || err "jq is required"

[[ -f "$VK_REGISTRY_SCRIPT" ]] || err "Not found: $VK_REGISTRY_SCRIPT"
[[ "$VERSION" =~ ^[0-9]+$ ]]   || err "version must be an integer >= 0"

# Ensure the convert-vk binary is available
if [[ ! -x "$CONVERT_VK_BIN" ]]; then
  log "Building convert-vk tool..."
  (cd "$NODE_DIR/../groth16-proofs" && cargo build --bin convert-vk --release --quiet) \
    || err "Failed to build convert-vk. Run: cd groth16-proofs && cargo build --bin convert-vk --release"
fi

# ─── Fetch manifest ───────────────────────────────────────────────────────────

log "Fetching manifest from $MANIFEST_URL..."
MANIFEST_JSON=$(curl -sfL "$MANIFEST_URL") || err "Failed to fetch manifest from $MANIFEST_URL"

PKG_VERSION=$(echo "$MANIFEST_JSON" | jq -r '.package_version')
CDN_BASE="$UNPKG_BASE/@orbinum/circuits@$PKG_VERSION"

log "Resolved @orbinum/circuits version: $PKG_VERSION"
log "Artifact base URL: $CDN_BASE"

# ─── Helpers ─────────────────────────────────────────────────────────────────

# Returns the active vk_json filename for a circuit from the manifest
get_vk_filename() {
  local circuit="$1"
  local active_version
  active_version=$(echo "$MANIFEST_JSON" | jq -r ".circuits[\"$circuit\"].active_version")
  echo "$MANIFEST_JSON" | jq -r ".circuits[\"$circuit\"].versions[\"$active_version\"].artifacts.vk_json.file"
}

TEMP_DIR=""

# Resolves a VK JSON path (local artifact or CDN download), then converts it
# to arkworks compressed binary format (.bin) required by the on-chain verifier.
resolve_vk() {
  local circuit="$1"
  local filename
  filename=$(get_vk_filename "$circuit")

  [[ "$filename" != "null" && -n "$filename" ]] \
    || err "Cannot resolve vk_json filename for circuit '$circuit' in manifest"

  # Always download from CDN — do not use local artifacts.
  # setup-dev.sh is the CDN workflow; use setup-dev-local.sh for local artifacts.
  if [[ -z "$TEMP_DIR" ]]; then
    TEMP_DIR=$(mktemp -d)
    log "Created temp directory: $TEMP_DIR"
  fi

  local url="$CDN_BASE/$filename"
  local json_path="$TEMP_DIR/$filename"
  log "Downloading $filename from $url..."
  curl -sfL "$url" -o "$json_path" || err "Failed to download $filename from $url"

  # Convert JSON → arkworks compressed binary
  local bin_path="${json_path%.json}.bin"
  "$CONVERT_VK_BIN" "$json_path" "$bin_path" \
    || err "Failed to convert $filename to binary"
  echo "$bin_path"
}

# ─── Resolve VKs ─────────────────────────────────────────────────────────────

log "Setting up DEV VKs"
log "RPC: $RPC_WS | Circuit version: $VERSION"

VK_TRANSFER=$(resolve_vk "transfer")
VK_UNSHIELD=$(resolve_vk "unshield")
VK_VALUE_PROOF=$(resolve_vk "value_proof")

log "Circuits: transfer(1), unshield(2), value_proof(6)"

# ─── Register + activate ─────────────────────────────────────────────────────

log "Batch registering + activating all 3 circuits (v$VERSION) in a single tx..."
bash "$VK_REGISTRY_SCRIPT" batch-register \
  "$VERSION" 1 \
  "$VK_TRANSFER" "$VK_UNSHIELD" "$VK_VALUE_PROOF" \
  "$RPC_WS" "$SUDO_SEED"

# ─── Cleanup ─────────────────────────────────────────────────────────────────

if [[ -n "$TEMP_DIR" ]]; then
  log "Cleaning up temp directory..."
  rm -rf "$TEMP_DIR"
fi

# Remove any .bin files produced from local artifacts (they are generated
# artefacts and are excluded from version control via .gitignore)
for circuit in transfer unshield value_proof; do
  rm -f "$ARTIFACTS_DIR/verification_key_${circuit}.bin"
done

log "DEV VKs configured successfully (circuits@$PKG_VERSION)"
