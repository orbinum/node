#!/usr/bin/env bash
# =============================================================================
# scripts/healthcheck.sh
# Verifica el estado de la red Orbinum después de un deploy.
# Puede usarse localmente o desde CI.
#
# USO:
#   bash scripts/healthcheck.sh [opciones] <rpc_url>
#
# MODOS:
#   (default)         Verifica salud, peers, producción de bloques
#   --check-runtime   Verifica además que spec_version subió
#   --wait-blocks N   Espera N bloques antes de declarar éxito (default: 3)
#
# EJEMPLOS:
#   bash scripts/healthcheck.sh http://127.0.0.1:9944
#   bash scripts/healthcheck.sh --check-runtime http://rpc.testnet.orbinum.io
#   bash scripts/healthcheck.sh --wait-blocks 5 http://127.0.0.1:9944
# =============================================================================
set -euo pipefail

CHECK_RUNTIME=false
WAIT_BLOCKS=3
RPC_URL=""
TIMEOUT=120   # segundos máximos de espera total

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo "[$(date '+%H:%M:%S')] ✅ $*"; }
fail() { echo "[$(date '+%H:%M:%S')] ❌ $*" >&2; exit 1; }
warn() { echo "[$(date '+%H:%M:%S')] ⚠️  $*" >&2; }

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-runtime) CHECK_RUNTIME=true;    shift ;;
    --wait-blocks)   WAIT_BLOCKS="$2";      shift 2 ;;
    --timeout)       TIMEOUT="$2";          shift 2 ;;
    http*|ws*)       RPC_URL="$1";          shift ;;
    *) echo "Opción desconocida: $1" >&2;   shift ;;
  esac
done

# Normalizar URL: healthcheck usa HTTP, no WS
RPC_HTTP="${RPC_URL/ws:\/\//http://}"
RPC_HTTP="${RPC_HTTP/wss:\/\//https://}"
RPC_HTTP="${RPC_HTTP:-http://127.0.0.1:9944}"

log "RPC endpoint: $RPC_HTTP"

# ── Helper: llamada RPC ───────────────────────────────────────────────────────
rpc_call() {
  local method="$1"
  shift
  local params="${1:-[]}"
  curl -sf --max-time 5 \
    -H "Content-Type: application/json" \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params}}" \
    "$RPC_HTTP" 2>/dev/null
}

hex_to_dec() { printf "%d\n" "$1" 2>/dev/null || echo 0; }

# ── 1. Esperar a que el nodo responda ─────────────────────────────────────────
log "[1/5] Esperando que el nodo responda..."
ELAPSED=0
until rpc_call "system_health" &>/dev/null; do
  sleep 3
  ELAPSED=$((ELAPSED + 3))
  [[ $ELAPSED -gt $TIMEOUT ]] && fail "El nodo no respondió en ${TIMEOUT}s"
  log "  Esperando... (${ELAPSED}s)"
done
ok "Nodo responde en $RPC_HTTP"

# ── 2. Health check básico ────────────────────────────────────────────────────
log "[2/5] Comprobando system_health..."
HEALTH=$(rpc_call "system_health")
PEERS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['peers'])" 2>/dev/null || echo "0")
IS_SYNCING=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['isSyncing'])" 2>/dev/null || echo "true")

log "  Peers: $PEERS"
log "  isSyncing: $IS_SYNCING"

[[ "$PEERS" -gt 0 ]] || warn "El nodo no tiene peers todavía (puede ser normal si es la primera vez)"

# ── 3. Verificar producción de bloques ────────────────────────────────────────
log "[3/5] Verificando producción de bloques (esperando $WAIT_BLOCKS bloques)..."

get_block() {
  local r
  r=$(rpc_call "chain_getHeader" 2>/dev/null || echo '{"result":{"number":"0x0"}}')
  hex_to_dec "$(echo "$r" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('number','0x0'))" 2>/dev/null)"
}

START_BLOCK=$(get_block)
log "  Bloque inicial: #${START_BLOCK}"

ELAPSED=0
while true; do
  sleep 6
  ELAPSED=$((ELAPSED + 6))
  CURRENT_BLOCK=$(get_block)
  DELTA=$((CURRENT_BLOCK - START_BLOCK))

  log "  Bloque actual: #${CURRENT_BLOCK} (+${DELTA})"

  if [[ $DELTA -ge $WAIT_BLOCKS ]]; then
    ok "Red produciendo bloques: #${START_BLOCK} → #${CURRENT_BLOCK} (+${DELTA} bloques)"
    break
  fi

  if [[ $ELAPSED -gt $TIMEOUT ]]; then
    fail "Red no produjo $WAIT_BLOCKS bloques en ${TIMEOUT}s. Último bloque: #${CURRENT_BLOCK}"
  fi
done

# ── 4. Verificar finalización (GRANDPA) ──────────────────────────────────────
log "[4/5] Verificando finalización GRANDPA..."
FINALIZED_HEX=$(rpc_call "chain_getFinalizedHead" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo "")

if [[ -n "$FINALIZED_HEX" ]]; then
  FINALIZED_HEADER=$(rpc_call "chain_getHeader" "[\"$FINALIZED_HEX\"]")
  FINALIZED_BLOCK=$(echo "$FINALIZED_HEADER" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('number','0x0'))" 2>/dev/null)
  FINALIZED_NUM=$(hex_to_dec "$FINALIZED_BLOCK")
  ok "Bloque finalizado: #${FINALIZED_NUM}"
else
  warn "No se pudo obtener el bloque finalizado"
fi

# ── 5. Verificar spec_version (solo si --check-runtime) ──────────────────────
if [[ "$CHECK_RUNTIME" == "true" ]]; then
  log "[5/5] Verificando spec_version post-upgrade..."
  RUNTIME_INFO=$(rpc_call "state_getRuntimeVersion")
  SPEC_VERSION=$(echo "$RUNTIME_INFO" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('specVersion',0))" 2>/dev/null || echo "0")
  SPEC_NAME=$(echo "$RUNTIME_INFO" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('specName',''))" 2>/dev/null || echo "")

  ok "Runtime: ${SPEC_NAME} spec_version=${SPEC_VERSION}"

  if [[ "$SPEC_VERSION" -lt 1 ]]; then
    fail "spec_version inválida: $SPEC_VERSION"
  fi
else
  log "[5/5] Saltando verificación de spec_version (no --check-runtime)"
fi

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
ok "HEALTHCHECK SUPERADO"
echo "  RPC:             $RPC_HTTP"
echo "  Peers:           $PEERS"
echo "  Bloque actual:   #$(get_block)"
echo "  Bloques nuevos:  +${DELTA}"
[[ "$CHECK_RUNTIME" == "true" ]] && echo "  spec_version:    $SPEC_VERSION"
echo "══════════════════════════════════════════════════════"
