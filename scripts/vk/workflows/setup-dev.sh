#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# scripts/vk/workflows/setup-dev.sh
# DEV setup for on-chain VKs (main entrypoint for developers)
#
# Registers + activates these circuits:
#   1 transfer, 2 unshield  — at the manifest's active version (or the one given)
#   3 shield                — at its own active version, when the package ships it
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
#   bash scripts/vk/workflows/setup-dev.sh ws://127.0.0.1:9944 "//Alice" 3
#   bash scripts/vk/workflows/setup-dev.sh ws://10.0.0.5:9944 "<mnemonic>" 2 "@orbinum/circuits@0.4.4"
# ============================================================================

RPC_WS="${1:-ws://127.0.0.1:9944}"
SUDO_SEED="${2:-//Alice}"
VERSION="${3:-}"
NPM_PACKAGE="${4:-@orbinum/circuits}"

UNPKG_BASE="https://unpkg.com"
MANIFEST_URL="$UNPKG_BASE/$NPM_PACKAGE/manifest.json"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VK_REGISTRY_SCRIPT="$SCRIPT_DIR/../lib/registry.sh"
ARTIFACTS_DIR="$NODE_DIR/artifacts"
PACK_VERIFYING_KEY_BIN="$NODE_DIR/../groth16-proofs/target/release/pack-verifying-key"

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
[[ -z "$VERSION" || "$VERSION" =~ ^[0-9]+$ ]] || err "version must be an integer >= 0"

# Ensure the pack-verifying-key binary is available
if [[ ! -x "$PACK_VERIFYING_KEY_BIN" ]]; then
  log "Building pack-verifying-key tool..."
  (cd "$NODE_DIR/../groth16-proofs" && cargo build --bin pack-verifying-key --release --quiet) \
    || err "Failed to build pack-verifying-key. Run: cd groth16-proofs && cargo build --bin pack-verifying-key --release"
fi

# ─── Fetch manifest ───────────────────────────────────────────────────────────

log "Fetching manifest from $MANIFEST_URL..."
MANIFEST_JSON=$(curl -sfL "$MANIFEST_URL") || err "Failed to fetch manifest from $MANIFEST_URL"

PKG_VERSION=$(echo "$MANIFEST_JSON" | jq -r '.package_version')
CDN_BASE="$UNPKG_BASE/@orbinum/circuits@$PKG_VERSION"

log "Resolved @orbinum/circuits version: $PKG_VERSION"

# Register the keys under the version the manifest serves as active, unless told
# otherwise: registering them under another number makes every client's VK-hash
# check fail.
if [[ -z "$VERSION" ]]; then
  VERSION=$(echo "$MANIFEST_JSON" | jq -r '.circuits["transfer"].active_version')
  [[ "$VERSION" =~ ^[0-9]+$ ]] || err "manifest has no active_version for transfer"
fi
log "Artifact base URL: $CDN_BASE"

# ─── Helpers ─────────────────────────────────────────────────────────────────

# The vk_json filename of $VERSION for a circuit, from the manifest: the key
# registered must be the one the manifest publishes under that version.
get_vk_filename() {
  local circuit="$1" version="${2:-$VERSION}"
  echo "$MANIFEST_JSON" | jq -r ".circuits[\"$circuit\"].versions[\"$version\"].artifacts.vk_json.file"
}

TEMP_DIR=""

# Resolves a VK JSON path (local artifact or CDN download), then converts it
# to arkworks compressed binary format (.bin) required by the on-chain verifier.
resolve_vk() {
  local circuit="$1" version="${2:-$VERSION}"
  local filename
  filename=$(get_vk_filename "$circuit" "$version")

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
  "$PACK_VERIFYING_KEY_BIN" "$json_path" "$bin_path" \
    || err "Failed to convert $filename to binary"
  echo "$bin_path"
}

# ─── Resolve VKs ─────────────────────────────────────────────────────────────

log "Setting up DEV VKs"
log "RPC: $RPC_WS | Circuit version: $VERSION"

VK_TRANSFER=$(resolve_vk "transfer")
VK_UNSHIELD=$(resolve_vk "unshield")

log "Circuits: transfer(1), unshield(2)"

# ─── Register + activate ─────────────────────────────────────────────────────

log "Batch registering + activating both circuits (v$VERSION) in a single tx..."
bash "$VK_REGISTRY_SCRIPT" batch-register \
  "$VERSION" 1 \
  "$VK_TRANSFER" "$VK_UNSHIELD" \
  "$RPC_WS" "$SUDO_SEED"

# Shield versions on its own axis, so it registers at its own active version. The
# first key of a circuit is activated on registration.
SHIELD_VERSION=$(echo "$MANIFEST_JSON" | jq -r '.circuits["shield"].active_version // empty')
if [[ -n "$SHIELD_VERSION" ]]; then
  VK_SHIELD=$(resolve_vk "shield" "$SHIELD_VERSION")
  log "Registering shield(3) v$SHIELD_VERSION..."
  bash "$VK_REGISTRY_SCRIPT" register 3 "$SHIELD_VERSION" "$VK_SHIELD" "$RPC_WS" "$SUDO_SEED"
else
  log "WARN: circuits@$PKG_VERSION ships no shield circuit — shield stays unusable on this chain"
fi

# ─── Cleanup ─────────────────────────────────────────────────────────────────

if [[ -n "$TEMP_DIR" ]]; then
  log "Cleaning up temp directory..."
  rm -rf "$TEMP_DIR"
fi

# Remove any .bin files produced from local artifacts (they are generated
# artefacts and are excluded from version control via .gitignore)
for circuit in transfer unshield shield; do
  rm -f "$ARTIFACTS_DIR/verification_key_${circuit}.bin"
done

log "DEV VKs configured successfully (circuits@$PKG_VERSION)"
