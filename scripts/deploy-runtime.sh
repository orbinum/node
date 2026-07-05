#!/usr/bin/env bash
# =============================================================================
# scripts/deploy-runtime.sh
# Envía un runtime upgrade on-chain via sudo.sudoUncheckedWeight(system.setCode)
#
# USO:
#   bash scripts/deploy-runtime.sh <wasm_file> <rpc_ws_url> <sudo_seed>
#
# EJEMPLOS:
#   # Desde CI (variables de entorno)
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
# DEPENDENCIAS:
#   Node.js 20+, @polkadot/api, @polkadot/keyring (installed in scripts/vk/node_modules)
#   npm install --prefix scripts/vk @polkadot/api @polkadot/keyring
# =============================================================================
set -euo pipefail

WASM_FILE="${1:?Falta WASM file. Uso: $0 <wasm> <rpc_ws> <sudo_seed>}"
RPC_WS="${2:?Falta RPC WS URL}"
SUDO_SEED="${3:?Falta sudo seed/mnemónica}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VK_DIR="$SCRIPT_DIR/vk"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

# ── Validaciones ──────────────────────────────────────────────────────────────
[[ -f "$WASM_FILE" ]] || err "WASM no encontrado: $WASM_FILE"

WASM_SIZE=$(wc -c < "$WASM_FILE")
WASM_KB=$((WASM_SIZE / 1024))
log "WASM: $WASM_FILE (${WASM_KB} KB)"

command -v node &>/dev/null || err "Node.js no encontrado"

# ── Instalar dependencias si no existen ──────────────────────────────────────
if [[ ! -d "$VK_DIR/node_modules/@polkadot/api" ]]; then
  log "Instalando dependencias JS..."
  cd "$VK_DIR"
  npm install --silent @polkadot/api @polkadot/keyring
  cd - > /dev/null
fi

export NODE_PATH="$VK_DIR/node_modules${NODE_PATH:+:$NODE_PATH}"

# ── Ejecutar el upgrade via Node.js ──────────────────────────────────────────
log "Conectando a $RPC_WS..."
log "Enviando sudo.sudoUncheckedWeight(system.setCode)..."

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

  // Leer WASM como hex
  const wasmHex = '0x' + fs.readFileSync(wasmFile).toString('hex');

  // Leer spec_version actual
  const currentVersion = api.runtimeVersion.specVersion.toNumber();
  console.log(`[info] spec_version actual en la red: ${currentVersion}`);

  // Construir la llamada interna system.setCode(wasm)
  const setCode = api.tx.system.setCode(wasmHex);

  // Envolver en sudo.sudoUncheckedWeight para saltarse el weight check
  const sudoCall = api.tx.sudo.sudoUncheckedWeight(setCode, { refTime: 0, proofSize: 0 });

  console.log('[info] Firmando y enviando transacción...');

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
          console.log('[success] system.CodeUpdated emitido — runtime upgrade incluido en el bloque');
        }
        if (api.events.sudo.Sudid.is(event)) {
          const [result] = event.data;
          if (result.isErr) {
            reject(new Error(`sudo.Sudid falló: ${result.asErr}`));
          }
        }
      });

      if (status.isFinalized) {
        console.log(`[success] Bloque finalizado: ${status.asFinalized}`);
        resolve();
      }
    }).catch(reject);
  });

  // Verificar que la spec_version subió
  await api.disconnect();
  const provider2 = new WsProvider(rpcWs);
  const api2      = await ApiPromise.create({ provider: provider2 });
  const newVersion = api2.runtimeVersion.specVersion.toNumber();
  console.log(`[verify] spec_version nueva en la red: ${newVersion}`);
  if (newVersion <= currentVersion) {
    console.warn(`[warn] spec_version no subió (${currentVersion} → ${newVersion}). ¿Olvidaste incrementarla en lib.rs?`);
  }
  await api2.disconnect();
  process.exit(0);
})().catch(e => { console.error('[fatal]', e.message); process.exit(1); });
JS

log "Runtime upgrade completado."
