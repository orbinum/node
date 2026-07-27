#!/usr/bin/env bash
# =============================================================================
# scripts/deploy-runtime.sh
# Sends an on-chain runtime upgrade via sudo.sudoUncheckedWeight(system.setCode)
#
# USAGE:
#   bash scripts/deploy-runtime.sh <wasm_file> <rpc_ws_url> <sudo_seed>
#
# EXAMPLES:
#   # From CI (environment variables)
#   bash scripts/deploy-runtime.sh \
#     target/release/wbuild/orbinum-runtime/orbinum_runtime.compact.compressed.wasm \
#     "$RPC_URL" "$SUDO_SEED"
#
#   # Manual testnet
#   bash scripts/deploy-runtime.sh \
#     ./orbinum_runtime.compact.compressed.wasm \
#     ws://rpc.testnet.orbinum.io \
#     "//Alice"
#
# DEPENDENCIES:
#   Node.js 20+, @polkadot/api, @polkadot/keyring (installed in scripts/vk/node_modules)
#   npm install --prefix scripts/vk @polkadot/api @polkadot/keyring
# =============================================================================
set -euo pipefail

WASM_FILE="${1:?Missing WASM file. Usage: $0 <wasm> <rpc_ws> <sudo_seed>}"
RPC_WS="${2:?Missing RPC WS URL}"
SUDO_SEED="${3:?Missing sudo seed/mnemonic}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VK_DIR="$SCRIPT_DIR/vk"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

# ── Validation ────────────────────────────────────────────────────────────────
[[ -f "$WASM_FILE" ]] || err "WASM not found: $WASM_FILE"

WASM_SIZE=$(wc -c < "$WASM_FILE")
WASM_KB=$((WASM_SIZE / 1024))
log "WASM: $WASM_FILE (${WASM_KB} KB)"

command -v node &>/dev/null || err "Node.js not found"

# ── Install dependencies if missing ───────────────────────────────────────────
if [[ ! -d "$VK_DIR/node_modules/@polkadot/api" ]]; then
  log "Installing JS dependencies..."
  cd "$VK_DIR"
  npm install --silent @polkadot/api @polkadot/keyring
  cd - > /dev/null
fi

export NODE_PATH="$VK_DIR/node_modules${NODE_PATH:+:$NODE_PATH}"

# ── Run the upgrade via Node.js ───────────────────────────────────────────────
log "Connecting to $RPC_WS..."
log "Sending sudo.sudoUncheckedWeight(system.setCode)..."

node - "$WASM_FILE" "$RPC_WS" "$SUDO_SEED" << 'JS'
const fs   = require('fs');

const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring }                = require('@polkadot/keyring');

const [,, wasmFile, rpcWs, sudoSeed] = process.argv;

(async () => {
  const provider = new WsProvider(rpcWs);
  const api      = await ApiPromise.create({ provider });

  const keyring  = new Keyring({ type: 'sr25519' });
  const sudoPair = keyring.addFromUri(sudoSeed);

  // Read WASM as hex
  const wasmHex = '0x' + fs.readFileSync(wasmFile).toString('hex');

  // Read current spec_version
  const currentVersion = api.runtimeVersion.specVersion.toNumber();
  console.log(`[info] current on-chain spec_version: ${currentVersion}`);

  // Build the inner system.setCode(wasm) call
  const setCode = api.tx.system.setCode(wasmHex);

  // Wrap in sudo.sudoUncheckedWeight to skip the weight check
  const sudoCall = api.tx.sudo.sudoUncheckedWeight(setCode, { refTime: 0, proofSize: 0 });

  console.log('[info] Signing and sending transaction...');

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

      events.forEach(({ event }) => {
        if (api.events.system.CodeUpdated.is(event)) {
          console.log('[success] system.CodeUpdated emitted — runtime upgrade included in the block');
        }
        if (api.events.sudo.Sudid.is(event)) {
          const [result] = event.data;
          if (result.isErr) {
            reject(new Error(`sudo.Sudid failed: ${result.asErr}`));
          }
        }
      });

      // Resolve on isInBlock, not isFinalized: setCode swaps the runtime, and the
      // long wait to finalization frequently outlives the WS connection (observed
      // 1006 abnormal closure ~3 min in). Inclusion in a block is enough to
      // confirm the upgrade applied; spec_version is re-checked below regardless.
      if (status.isInBlock) {
        console.log(`[success] Included in block: ${status.asInBlock}`);
        resolve();
      }
    }).catch(reject);
  });

  // Verify spec_version rose
  await api.disconnect();
  const provider2 = new WsProvider(rpcWs);
  const api2      = await ApiPromise.create({ provider: provider2 });
  const newVersion = api2.runtimeVersion.specVersion.toNumber();
  console.log(`[verify] new on-chain spec_version: ${newVersion}`);
  if (newVersion <= currentVersion) {
    console.warn(`[warn] spec_version did not rise (${currentVersion} → ${newVersion}). Did you forget to bump it in lib.rs?`);
  }
  await api2.disconnect();
  process.exit(0);
})().catch(e => { console.error('[fatal]', e.message); process.exit(1); });
JS

log "Runtime upgrade complete."
