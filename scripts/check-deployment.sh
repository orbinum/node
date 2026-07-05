#!/usr/bin/env bash
# Verifica qué versión de binario (impl) y runtime (spec) está corriendo cada
# nodo, sobre uno o varios endpoints RPC. Úsalo para confirmar que un update de
# imagen (Watchtower) o un runtime upgrade (setCode) llegó a la flota.
#
# Uso:
#   scripts/check-deployment.sh <rpc_url> [<rpc_url> ...]
#   scripts/check-deployment.sh --expect-spec 2 <rpc_url> ...
#   scripts/check-deployment.sh --expect-impl 0.2.0 <rpc_url> ...
#
# Ejemplos:
#   scripts/check-deployment.sh https://rpc.testnet.orbinum.io
#   scripts/check-deployment.sh --expect-spec 2 \
#     https://rpc.testnet.orbinum.io ws://10.0.0.2:9944
#
# Salida por nodo: spec_version, impl_name/version, client version, mejor bloque
# y bloque finalizado. Exit != 0 si algún nodo no responde o no cumple --expect-*.
set -euo pipefail

EXPECT_SPEC=""   # spec_version esperado (runtime upgrade)
EXPECT_IMPL=""   # substrato de la versión de cliente esperada (imagen/binario)
RPCS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-spec) EXPECT_SPEC="$2"; shift 2 ;;
    --expect-impl) EXPECT_IMPL="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//; 1d'; exit 0 ;;
    http*|ws*) RPCS+=("$1"); shift ;;
    *) echo "Argumento no reconocido: $1" >&2; exit 2 ;;
  esac
done

if [[ ${#RPCS[@]} -eq 0 ]]; then
  echo "Falta al menos un RPC url. Uso: $0 [--expect-spec N] [--expect-impl X] <rpc_url> ..." >&2
  exit 2
fi

# ── Helper: llamada RPC (mismo patrón que healthcheck.sh) ─────────────────────
rpc_call() {
  local url="$1" method="$2" params="${3:-[]}"
  # normaliza ws(s):// → http(s)://
  url="${url/ws:\/\//http://}"; url="${url/wss:\/\//https://}"
  curl -sf --max-time 8 \
    -H "Content-Type: application/json" \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params}}" \
    "$url" 2>/dev/null
}

# extrae un campo del JSON result con python3 (siempre disponible en los runners)
jget() { python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('$1',''))" 2>/dev/null || echo ""; }
jget_raw() { python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo ""; }
hex_to_dec() { [[ "$1" == 0x* ]] && printf "%d\n" "$1" 2>/dev/null || echo "${1:-0}"; }

FAIL=0

for url in "${RPCS[@]}"; do
  echo "── $url"

  RTV=$(rpc_call "$url" "state_getRuntimeVersion") || RTV=""
  if [[ -z "$RTV" ]]; then
    echo "   ✗ sin respuesta (state_getRuntimeVersion)"
    FAIL=1
    continue
  fi

  SPEC=$(echo "$RTV" | jget "specVersion")
  IMPL_NAME=$(echo "$RTV" | jget "implName")
  IMPL_VER=$(echo "$RTV" | jget "implVersion")

  CLIENT=$(rpc_call "$url" "system_version" | jget_raw)

  HEALTH=$(rpc_call "$url" "system_health")
  PEERS=$(echo "$HEALTH" | jget "peers")

  BEST_HEX=$(rpc_call "$url" "chain_getHeader" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('number',''))" 2>/dev/null || echo "")
  FIN_HASH=$(rpc_call "$url" "chain_getFinalizedHead" | jget_raw)
  FIN_HEX=$(rpc_call "$url" "chain_getHeader" "[\"$FIN_HASH\"]" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('number',''))" 2>/dev/null || echo "")

  echo "   spec_version : ${SPEC:-?}"
  echo "   impl         : ${IMPL_NAME:-?} v${IMPL_VER:-?}"
  echo "   client       : ${CLIENT:-?}"
  echo "   peers        : ${PEERS:-?}"
  echo "   best block   : $(hex_to_dec "${BEST_HEX:-0}")"
  echo "   finalized    : $(hex_to_dec "${FIN_HEX:-0}")"

  # ── chequeos --expect-* ─────────────────────────────────────────────────────
  if [[ -n "$EXPECT_SPEC" && "$SPEC" != "$EXPECT_SPEC" ]]; then
    echo "   ✗ spec_version esperado=$EXPECT_SPEC, actual=$SPEC"
    FAIL=1
  fi
  if [[ -n "$EXPECT_IMPL" && "$CLIENT" != *"$EXPECT_IMPL"* ]]; then
    echo "   ✗ client esperado contiene '$EXPECT_IMPL', actual=$CLIENT"
    FAIL=1
  fi
  if [[ -z "$EXPECT_SPEC" && -z "$EXPECT_IMPL" ]]; then
    echo "   ✓ responde"
  elif [[ $FAIL -eq 0 ]]; then
    echo "   ✓ versión esperada"
  fi
done

if [[ $FAIL -ne 0 ]]; then
  echo ""
  echo "Resultado: al menos un nodo no responde o no cumple la versión esperada."
  exit 1
fi
echo ""
echo "Resultado: todos los nodos OK."
