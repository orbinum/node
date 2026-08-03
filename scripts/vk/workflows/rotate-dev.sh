#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# scripts/vk/workflows/rotate-dev.sh
# DEV on-chain VK rotation for the 3 supported circuits.
#
# Flow:
#   1) register NEW_VERSION on 1,2,6
#   2) set-active NEW_VERSION on 1,2,6
#   3) RPC validation per circuit
#   4) optional: remove OLD_VERSION on 1,2,6 (if --remove-old)
#
# USAGE:
#   bash scripts/vk/workflows/rotate-dev.sh <new_version> [rpc_ws] [sudo_seed] [old_version]
#
# FLAGS:
#   --remove-old   removes old_version at the end (default: do not remove)
#
# EXAMPLES:
#   bash scripts/vk/workflows/rotate-dev.sh 2
#   bash scripts/vk/workflows/rotate-dev.sh 2 ws://127.0.0.1:9944 "//Alice" 1
#   bash scripts/vk/workflows/rotate-dev.sh 2 ws://127.0.0.1:9944 "//Alice" 1 --remove-old
# ============================================================================

NEW_VERSION="${1:-}"
RPC_WS="${2:-ws://127.0.0.1:9944}"
SUDO_SEED="${3:-//Alice}"
OLD_VERSION="${4:-1}"
REMOVE_OLD=false

for arg in "$@"; do
  if [[ "$arg" == "--remove-old" ]]; then
    REMOVE_OLD=true
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VK_REGISTRY_SCRIPT="$SCRIPT_DIR/../lib/registry.sh"
VERIFY_WINDOW_SCRIPT="$SCRIPT_DIR/../policy/verify-window-dev.sh"
ARTIFACTS_DIR="$NODE_DIR/artifacts"
CONVERT_VK_BIN="$NODE_DIR/../groth16-proofs/target/release/convert-vk"

RPC_HTTP="${RPC_WS/ws:\/\//http://}"
RPC_HTTP="${RPC_HTTP/wss:\/\//https://}"

err() {
  echo "[ERROR] $*" >&2
  exit 1
}

log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

[[ -n "$NEW_VERSION" ]] || err "Missing <new_version>. Usage: bash scripts/vk/workflows/rotate-dev.sh <new_version> [rpc_ws] [sudo_seed] [old_version] [--remove-old]"
[[ "$NEW_VERSION" =~ ^[0-9]+$ ]] || err "new_version must be an integer >= 0"
[[ "$OLD_VERSION" =~ ^[0-9]+$ ]] || err "old_version must be an integer >= 0"
[[ "$NEW_VERSION" != "$OLD_VERSION" ]] || err "new_version and old_version cannot be equal"
[[ -f "$VK_REGISTRY_SCRIPT" ]] || err "Not found: $VK_REGISTRY_SCRIPT"
[[ -f "$VERIFY_WINDOW_SCRIPT" ]] || err "Not found: $VERIFY_WINDOW_SCRIPT"

# Ensure the convert-vk binary is available
if [[ ! -x "$CONVERT_VK_BIN" ]]; then
  log "Building convert-vk tool..."
  (cd "$NODE_DIR/../groth16-proofs" && cargo build --bin convert-vk --release --quiet) \
    || err "Failed to build convert-vk. Run: cd groth16-proofs && cargo build --bin convert-vk --release"
fi

# Convert each JSON VK to arkworks compressed binary and return the .bin path
convert_vk() {
  local json_path="$1"
  local bin_path="${json_path%.json}.bin"
  "$CONVERT_VK_BIN" "$json_path" "$bin_path" \
    || err "Failed to convert $(basename "$json_path") to binary"
  echo "$bin_path"
}

VK_TRANSFER_BIN=$(convert_vk "$ARTIFACTS_DIR/verification_key_transfer.json")
VK_UNSHIELD_BIN=$(convert_vk "$ARTIFACTS_DIR/verification_key_unshield.json")
VK_VALUE_PROOF_BIN=$(convert_vk "$ARTIFACTS_DIR/verification_key_value_proof.json")

validate_rpc() {
  local circuit_id="$1"
  local label="$2"

  local response
  response=$(curl -s -H "Content-Type: application/json" \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"zkVerifier_getCircuitVersionInfo\",\"params\":[${circuit_id}]}" \
    "$RPC_HTTP")

  local active
  active=$(printf '%s' "$response" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("result",{}).get("active_version",""))' 2>/dev/null || true)

  [[ "$active" == "$NEW_VERSION" ]] || err "[$label] active_version expected=$NEW_VERSION current=$active"
  log "[$label] RPC ok (active_version=$active)"
}

remove_old() {
  local circuit_id="$1"
  local label="$2"

  log "[$label] remove old v$OLD_VERSION"
  bash "$VK_REGISTRY_SCRIPT" remove "$circuit_id" "$OLD_VERSION" "$RPC_WS" "$SUDO_SEED"
}

log "Starting DEV VK rotation"
log "RPC: $RPC_WS"
log "old_version: $OLD_VERSION"
log "new_version: $NEW_VERSION"
log "remove_old: $REMOVE_OLD"

# Register and activate all 3 circuits in ONE atomic transaction
log "Batch registering + activating all 3 circuits (v$NEW_VERSION) in a single tx..."
bash "$VK_REGISTRY_SCRIPT" batch-register \
  "$NEW_VERSION" 1 \
  "$VK_TRANSFER_BIN" "$VK_UNSHIELD_BIN" "$VK_VALUE_PROOF_BIN" \
  "$RPC_WS" "$SUDO_SEED"

validate_rpc 1 "transfer"
validate_rpc 2 "unshield"
validate_rpc 6 "value_proof"

if [[ "$REMOVE_OLD" == true ]]; then
  log "Checking pre-remove window (required=[${OLD_VERSION},${NEW_VERSION}])"
  bash "$VERIFY_WINDOW_SCRIPT" "$NEW_VERSION" "$RPC_HTTP" "${OLD_VERSION},${NEW_VERSION}" true

  remove_old 1 "transfer"
  remove_old 2 "unshield"
  remove_old 6 "value_proof"

  log "Checking post-remove state (required=[${NEW_VERSION}])"
  bash "$VERIFY_WINDOW_SCRIPT" "$NEW_VERSION" "$RPC_HTTP" "${NEW_VERSION}" false

  log "old_version v$OLD_VERSION removed from all 3 circuits"
fi

# Remove generated .bin files — they are build artefacts excluded from git
rm -f "$VK_TRANSFER_BIN" "$VK_UNSHIELD_BIN" "$VK_VALUE_PROOF_BIN"

log "✅ VK rotation completed"
