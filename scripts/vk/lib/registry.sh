#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/vk/lib/registry.sh
# Atomic on-chain verification key (VK) management in pallet-zk-verifier via sudo
#
# USAGE:
#   # Register/manage individual VKs:
#   bash scripts/vk/lib/registry.sh register <circuit_id> <version> <vk_file> <rpc_ws_url> <sudo_seed>
#   bash scripts/vk/lib/registry.sh set-active <circuit_id> <version> <rpc_ws_url> <sudo_seed>
#   bash scripts/vk/lib/registry.sh remove <circuit_id> <version> <rpc_ws_url> <sudo_seed>
#
#   # Register and activate all 3 circuits in ONE atomic transaction:
#   bash scripts/vk/lib/registry.sh batch-register <version> <set_active:1|0> \
#     <vk_transfer> <vk_unshield> <vk_value_proof> \
#     <rpc_ws_url> <sudo_seed>
#
# EXAMPLES:
#   bash scripts/vk/lib/registry.sh register 1 2 ./artifacts/verification_key_transfer.json ws://127.0.0.1:9944 "//Alice"
#   bash scripts/vk/lib/registry.sh set-active 1 2 ws://127.0.0.1:9944 "//Alice"
#   bash scripts/vk/lib/registry.sh remove 1 1 ws://127.0.0.1:9944 "//Alice"
#   bash scripts/vk/lib/registry.sh batch-register 1 1 \
#     ./artifacts/verification_key_transfer.json \
#     ./artifacts/verification_key_unshield.json \
#     ./artifacts/verification_key_value_proof.json \
#     ws://127.0.0.1:9944 "//Alice"
# =============================================================================

ACTION="${1:-}"
CIRCUIT_ID="${2:-}"
VERSION="${3:-}"

err() {
  echo "[ERROR] $*" >&2
  exit 1
}

log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

[[ -n "$ACTION" ]] || err "Missing action: register | set-active | remove | batch-register"
[[ -n "$CIRCUIT_ID" ]] || err "Missing circuit_id (or <version> for batch-register)"
[[ -n "$VERSION" ]] || err "Missing version"

# Initialize all optional variables to avoid unbound variable errors with set -u
VK_FILE=""
BATCH_VERSION=""
BATCH_SET_ACTIVE=""
BATCH_VK_TRANSFER=""
BATCH_VK_UNSHIELD=""
BATCH_VK_VALUE_PROOF=""
RPC_WS=""
SUDO_SEED=""

case "$ACTION" in
  register)
    VK_FILE="${4:-}"
    RPC_WS="${5:-}"
    SUDO_SEED="${6:-}"
    [[ -f "$VK_FILE" ]] || err "VK file not found: $VK_FILE"
    ;;
  set-active|remove)
    RPC_WS="${4:-}"
    SUDO_SEED="${5:-}"
    VK_FILE=""
    ;;
  batch-register)
    # For batch-register the positional args shift: $2=version $3=set_active $4..6=vk_files $7=rpc $8=seed
    # Re-read with cleaner names to avoid confusion with CIRCUIT_ID/VERSION used by other actions
    BATCH_VERSION="${2:-}"
    BATCH_SET_ACTIVE="${3:-1}"
    BATCH_VK_TRANSFER="${4:-}"
    BATCH_VK_UNSHIELD="${5:-}"
    BATCH_VK_VALUE_PROOF="${6:-}"
    RPC_WS="${7:-}"
    SUDO_SEED="${8:-}"
    [[ -n "$BATCH_VERSION" ]] || err "batch-register: missing <version>"
    [[ "$BATCH_VERSION" =~ ^[0-9]+$ ]] || err "batch-register: version must be an integer >= 0"
    [[ "$BATCH_SET_ACTIVE" =~ ^[01]$ ]] || err "batch-register: set_active must be 0 or 1"
    for _f in "$BATCH_VK_TRANSFER" "$BATCH_VK_UNSHIELD" "$BATCH_VK_VALUE_PROOF"; do
      [[ -f "$_f" ]] || err "VK file not found: $_f"
    done
    ;;
  *)
    err "Invalid action: $ACTION (use register | set-active | remove | batch-register)"
    ;;
esac

[[ -n "$RPC_WS" ]] || err "Missing RPC WS URL"
[[ -n "$SUDO_SEED" ]] || err "Missing sudo seed/mnemonic"

command -v node >/dev/null 2>&1 || err "Node.js not found"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -d "$VK_DIR/node_modules/@polkadot/api" ]]; then
  log "Installing JS dependencies..."
  cd "$VK_DIR"
  npm install --silent @polkadot/api @polkadot/keyring
  cd - >/dev/null
fi

export NODE_PATH="$VK_DIR/node_modules${NODE_PATH:+:$NODE_PATH}"

log "Action: $ACTION | circuit: $CIRCUIT_ID | version: $VERSION"
log "RPC: $RPC_WS"

node - "$ACTION" "$CIRCUIT_ID" "$VERSION" "$VK_FILE" "$RPC_WS" "$SUDO_SEED" \
      "$BATCH_VERSION" "$BATCH_SET_ACTIVE" \
      "$BATCH_VK_TRANSFER" "$BATCH_VK_UNSHIELD" "$BATCH_VK_VALUE_PROOF" << 'JS'
const fs = require('fs');
const path = require('path');
const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring } = require('@polkadot/keyring');

const [,, action, circuitIdRaw, versionRaw, vkFile, rpcWs, sudoSeed,
       batchVersion, batchSetActive,
       batchVkTransfer, batchVkUnshield, batchVkValueProof] = process.argv;

function assertNumber(name, value) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${name} must be an integer >= 0`);
  }
}

(async () => {
  // For non-batch actions parse circuit_id/version as before
  let circuitId, version;
  if (action !== 'batch-register') {
    circuitId = Number(circuitIdRaw);
    version   = Number(versionRaw);
    assertNumber('circuit_id', circuitId);
    assertNumber('version', version);
  }

  const provider = new WsProvider(rpcWs);
  const api = await ApiPromise.create({ provider });

  const keyring  = new Keyring({ type: 'sr25519' });
  const sudoPair = keyring.addFromUri(sudoSeed);

  let innerCall;

  if (action === 'register') {
    const vkData = fs.readFileSync(path.resolve(vkFile));
    if (!vkData.length) throw new Error('VK file is empty');

    innerCall = api.tx.zkVerifier.registerVerificationKey(
      circuitId,
      version,
      Array.from(vkData)
    );
  } else if (action === 'set-active') {
    innerCall = api.tx.zkVerifier.setActiveVersion(circuitId, version);
  } else if (action === 'remove') {
    innerCall = api.tx.zkVerifier.removeVerificationKey(circuitId, version);
  } else if (action === 'batch-register') {
    // circuit IDs: transfer=1, unshield=2, value_proof=6
    const ver      = Number(batchVersion);
    const setActive = batchSetActive === '1';
    assertNumber('batch_version', ver);

    const vkFiles = [
      { circuitId: 1, file: batchVkTransfer      },
      { circuitId: 2, file: batchVkUnshield       },
      { circuitId: 6, file: batchVkValueProof      },
    ];

    const entries = vkFiles.map(({ circuitId: cid, file }) => {
      const data = fs.readFileSync(path.resolve(file));
      if (!data.length) throw new Error(`VK file is empty: ${file}`);
      return {
        circuit_id:        cid,
        version:           ver,
        verification_key:  Array.from(data),
        set_active:        setActive,
      };
    });

    innerCall = api.tx.zkVerifier.batchRegisterVerificationKeys(entries);
  } else {
    throw new Error(`Unsupported action: ${action}`);
  }

  const sudoCall = api.tx.sudo.sudo(innerCall);

  await new Promise((resolve, reject) => {
    sudoCall.signAndSend(sudoPair, ({ status, events, dispatchError }) => {
      if (dispatchError) {
        if (dispatchError.isModule) {
          const decoded = api.registry.findMetaError(dispatchError.asModule);
          reject(new Error(`DispatchError: ${decoded.section}.${decoded.name}: ${decoded.docs}`));
        } else {
          reject(new Error(`DispatchError: ${dispatchError.toString()}`));
        }
        return;
      }

      for (const { event } of events) {
        if (api.events.sudo.Sudid.is(event)) {
          const [result] = event.data;
          if (result.isErr) {
            reject(new Error(`sudo.Sudid failed: ${result.asErr}`));
            return;
          }
        }
      }

      if (status.isFinalized) {
        console.log(`[success] Action ${action} finalized in block ${status.asFinalized}`);
        resolve();
      }
    }).catch(reject);
  });

  await api.disconnect();
})().catch((error) => {
  console.error('[fatal]', error.message);
  process.exit(1);
});
JS

log "VK operation completed"
