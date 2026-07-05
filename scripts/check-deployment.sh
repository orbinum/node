#!/usr/bin/env bash
# Reports which binary (impl) and runtime (spec) version each node is running,
# across one or more RPC endpoints. Use it to confirm an image update
# (Watchtower) or a runtime upgrade (setCode) reached the fleet.
#
# Usage:
#   scripts/check-deployment.sh <rpc_url> [<rpc_url> ...]
#   scripts/check-deployment.sh --expect-spec 2 <rpc_url> ...
#   scripts/check-deployment.sh --expect-impl 0.2.0 <rpc_url> ...
#
# Examples:
#   scripts/check-deployment.sh https://rpc.testnet.orbinum.io
#   scripts/check-deployment.sh --expect-spec 2 \
#     https://rpc.testnet.orbinum.io ws://10.0.0.2:9944
#
# Per-node output: spec_version, impl_name/version, client version, best block
# and finalized block. Exit != 0 if a node is unreachable or fails --expect-*.
set -euo pipefail

EXPECT_SPEC=""   # expected spec_version (runtime upgrade)
EXPECT_IMPL=""   # substring of the expected client version (image/binary)
RPCS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-spec) EXPECT_SPEC="$2"; shift 2 ;;
    --expect-impl) EXPECT_IMPL="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//; 1d'; exit 0 ;;
    http*|ws*) RPCS+=("$1"); shift ;;
    *) echo "Unrecognized argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ${#RPCS[@]} -eq 0 ]]; then
  echo "Need at least one RPC url. Usage: $0 [--expect-spec N] [--expect-impl X] <rpc_url> ..." >&2
  exit 2
fi

# ── Helper: RPC call (same pattern as healthcheck.sh) ─────────────────────────
rpc_call() {
  local url="$1" method="$2" params="${3:-[]}"
  # normalize ws(s):// → http(s)://
  url="${url/ws:\/\//http://}"; url="${url/wss:\/\//https://}"
  curl -sf --max-time 8 \
    -H "Content-Type: application/json" \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params}}" \
    "$url" 2>/dev/null
}

# extract a field from the JSON result with python3 (always present on runners)
jget() { python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('$1',''))" 2>/dev/null || echo ""; }
jget_raw() { python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo ""; }
hex_to_dec() { [[ "$1" == 0x* ]] && printf "%d\n" "$1" 2>/dev/null || echo "${1:-0}"; }

FAIL=0

for url in "${RPCS[@]}"; do
  echo "── $url"

  RTV=$(rpc_call "$url" "state_getRuntimeVersion") || RTV=""
  if [[ -z "$RTV" ]]; then
    echo "   ✗ no response (state_getRuntimeVersion)"
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

  # ── --expect-* checks ─────────────────────────────────────────────────────────
  if [[ -n "$EXPECT_SPEC" && "$SPEC" != "$EXPECT_SPEC" ]]; then
    echo "   ✗ spec_version expected=$EXPECT_SPEC, actual=$SPEC"
    FAIL=1
  fi
  if [[ -n "$EXPECT_IMPL" && "$CLIENT" != *"$EXPECT_IMPL"* ]]; then
    echo "   ✗ client expected to contain '$EXPECT_IMPL', actual=$CLIENT"
    FAIL=1
  fi
  if [[ -z "$EXPECT_SPEC" && -z "$EXPECT_IMPL" ]]; then
    echo "   ✓ responding"
  elif [[ $FAIL -eq 0 ]]; then
    echo "   ✓ expected version"
  fi
done

if [[ $FAIL -ne 0 ]]; then
  echo ""
  echo "Result: at least one node is unreachable or off the expected version."
  exit 1
fi
echo ""
echo "Result: all nodes OK."
