#!/usr/bin/env bash
# =============================================================================
# scripts/healthcheck.sh
# Checks Orbinum network health after a deploy.
# Usable locally or from CI.
#
# USAGE:
#   bash scripts/healthcheck.sh [opciones] <rpc_url>
#
# MODES:
#   (default)         Checks health, peers, block production
#   --check-runtime   Also verifies spec_version rose
#   --wait-blocks N   Wait N blocks before declaring success (default: 3)
#
# EXAMPLES:
#   bash scripts/healthcheck.sh http://127.0.0.1:9944
#   bash scripts/healthcheck.sh --check-runtime http://rpc.testnet.orbinum.io
#   bash scripts/healthcheck.sh --wait-blocks 5 http://127.0.0.1:9944
# =============================================================================
set -euo pipefail

CHECK_RUNTIME=false
WAIT_BLOCKS=3
RPC_URL=""
TIMEOUT=120   # max total wait in seconds

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
    *) echo "Unknown option: $1" >&2;   shift ;;
  esac
done

# Normalize URL: healthcheck uses HTTP, not WS
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

# ── 1. Wait for the node to respond ───────────────────────────────────────────
log "[1/5] Waiting for the node to respond..."
ELAPSED=0
until rpc_call "system_health" &>/dev/null; do
  sleep 3
  ELAPSED=$((ELAPSED + 3))
  [[ $ELAPSED -gt $TIMEOUT ]] && fail "Node did not respond within ${TIMEOUT}s"
  log "  Waiting... (${ELAPSED}s)"
done
ok "Node responding at $RPC_HTTP"

# ── 2. Basic health check ─────────────────────────────────────────────────────
log "[2/5] Checking system_health..."
HEALTH=$(rpc_call "system_health")
PEERS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['peers'])" 2>/dev/null || echo "0")
IS_SYNCING=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['isSyncing'])" 2>/dev/null || echo "true")

log "  Peers: $PEERS"
log "  isSyncing: $IS_SYNCING"

[[ "$PEERS" -gt 0 ]] || warn "Node has no peers yet (may be normal on first start)"

# ── 3. Check block production ──────────────────────────────────────────────────
log "[3/5] Checking block production (waiting for $WAIT_BLOCKS blocks)..."

get_block() {
  local r
  r=$(rpc_call "chain_getHeader" 2>/dev/null || echo '{"result":{"number":"0x0"}}')
  hex_to_dec "$(echo "$r" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('number','0x0'))" 2>/dev/null)"
}

START_BLOCK=$(get_block)
log "  Start block: #${START_BLOCK}"

ELAPSED=0
while true; do
  sleep 6
  ELAPSED=$((ELAPSED + 6))
  CURRENT_BLOCK=$(get_block)
  DELTA=$((CURRENT_BLOCK - START_BLOCK))

  log "  Current block: #${CURRENT_BLOCK} (+${DELTA})"

  if [[ $DELTA -ge $WAIT_BLOCKS ]]; then
    ok "Network producing blocks: #${START_BLOCK} → #${CURRENT_BLOCK} (+${DELTA} blocks)"
    break
  fi

  if [[ $ELAPSED -gt $TIMEOUT ]]; then
    fail "Network did not produce $WAIT_BLOCKS blocks within ${TIMEOUT}s. Last block: #${CURRENT_BLOCK}"
  fi
done

# ── 4. Check finalization (GRANDPA) ────────────────────────────────────────────
log "[4/5] Checking GRANDPA finalization..."
FINALIZED_HEX=$(rpc_call "chain_getFinalizedHead" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo "")

if [[ -n "$FINALIZED_HEX" ]]; then
  FINALIZED_HEADER=$(rpc_call "chain_getHeader" "[\"$FINALIZED_HEX\"]")
  FINALIZED_BLOCK=$(echo "$FINALIZED_HEADER" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('number','0x0'))" 2>/dev/null)
  FINALIZED_NUM=$(hex_to_dec "$FINALIZED_BLOCK")
  ok "Finalized block: #${FINALIZED_NUM}"
else
  warn "Could not fetch the finalized block"
fi

# ── 5. Check spec_version (only with --check-runtime) ──────────────────────────
if [[ "$CHECK_RUNTIME" == "true" ]]; then
  log "[5/5] Checking spec_version post-upgrade..."
  RUNTIME_INFO=$(rpc_call "state_getRuntimeVersion")
  SPEC_VERSION=$(echo "$RUNTIME_INFO" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('specVersion',0))" 2>/dev/null || echo "0")
  SPEC_NAME=$(echo "$RUNTIME_INFO" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('specName',''))" 2>/dev/null || echo "")

  ok "Runtime: ${SPEC_NAME} spec_version=${SPEC_VERSION}"

  if [[ "$SPEC_VERSION" -lt 1 ]]; then
    fail "Invalid spec_version: $SPEC_VERSION"
  fi

  # ISMP identities, read off the chain that was just upgraded.
  #
  # `host_state_machine` is the exact call Tesseract makes to derive our identity, so a
  # deploy that does not answer it leaves the relayer unable to start. The coprocessor is
  # only warned about: this script does not know which environment it is pointed at, and
  # a wrong one is a build mistake that `verify-coprocessor.sh` catches before release.
  ISMP_HOST=$(rpc_call "state_call" '["IsmpRuntimeApi_host_state_machine","0x"]' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo "")

  if [[ "$ISMP_HOST" == "0x036f726269" ]]; then
    ok "ISMP host_state_machine: Substrate(\"orbi\")"
    ISMP_COP=$(rpc_call "state_call" '["OrbinumIsmpApi_coprocessor","0x"]' \
      | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo "")
    case "$ISMP_COP" in
      0x0102a90f0000) ok  "ISMP coprocessor: Kusama(4009) — testnet build"   ;;
      0x0101270d0000) ok  "ISMP coprocessor: Polkadot(3367) — mainnet build" ;;
      *)              warn "ISMP coprocessor unrecognised: '$ISMP_COP'"      ;;
    esac
  elif [[ -z "$ISMP_HOST" ]]; then
    warn "ISMP runtime API absent — this runtime predates the ISMP integration"
  else
    fail "ISMP host_state_machine is '$ISMP_HOST', not Substrate(\"orbi\"); Tesseract will not start"
  fi
else
  log "[5/5] Skipping spec_version check (no --check-runtime)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
ok "HEALTHCHECK PASSED"
echo "  RPC:             $RPC_HTTP"
echo "  Peers:           $PEERS"
echo "  Current block:   #$(get_block)"
echo "  New blocks:      +${DELTA}"
[[ "$CHECK_RUNTIME" == "true" ]] && echo "  spec_version:    $SPEC_VERSION"
echo "══════════════════════════════════════════════════════"
