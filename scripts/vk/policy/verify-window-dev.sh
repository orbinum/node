#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# scripts/vk/policy/verify-window-dev.sh
# Verifies VK version-window policy for fixed DEV circuits.
#
# Verified circuits: 1 (transfer), 2 (unshield), 6 (value_proof), 5 (private_link)
#
# USAGE:
#   bash scripts/vk/policy/verify-window-dev.sh <expected_active> [rpc_http] [required_versions_csv] [strict]
#
# PARAMETERS:
#   expected_active         version that must be active on all circuits
#   rpc_http                default: http://127.0.0.1:9944
#   required_versions_csv   default: expected_active (e.g., "1,2")
#   strict                  default: false
#                           - true: supported_versions must be EXACTLY required_versions
#                           - false: supported_versions must contain required_versions
#
# EXAMPLES:
#   bash scripts/vk/policy/verify-window-dev.sh 2
#   bash scripts/vk/policy/verify-window-dev.sh 2 http://127.0.0.1:9944 "1,2" true
# ============================================================================

EXPECTED_ACTIVE="${1:-}"
RPC_HTTP="${2:-http://127.0.0.1:9944}"
REQUIRED_CSV="${3:-${EXPECTED_ACTIVE}}"
STRICT="${4:-false}"

err() {
  echo "[ERROR] $*" >&2
  exit 1
}

log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

[[ -n "$EXPECTED_ACTIVE" ]] || err "Missing <expected_active>"
[[ "$EXPECTED_ACTIVE" =~ ^[0-9]+$ ]] || err "expected_active must be an integer >= 0"
[[ "$STRICT" == "true" || "$STRICT" == "false" ]] || err "strict must be true|false"

CIRCUITS=(1 2 6 5)

log "Verifying VK window"
log "RPC: $RPC_HTTP"
log "expected_active: $EXPECTED_ACTIVE"
log "required_versions: $REQUIRED_CSV"
log "strict: $STRICT"

for cid in "${CIRCUITS[@]}"; do
  response=$(curl -s -H "Content-Type: application/json" \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"zkVerifier_getCircuitVersionInfo\",\"params\":[${cid}]}" \
    "$RPC_HTTP")

  python3 - "$cid" "$EXPECTED_ACTIVE" "$REQUIRED_CSV" "$STRICT" "$response" <<'PY'
import json
import sys

cid = int(sys.argv[1])
expected_active = int(sys.argv[2])
required = [int(x.strip()) for x in sys.argv[3].split(',') if x.strip()]
strict = sys.argv[4].lower() == 'true'
raw = sys.argv[5]

try:
    payload = json.loads(raw)
except Exception as e:
    print(f"[ERROR] circuit {cid}: invalid JSON response: {e}")
    sys.exit(1)

result = payload.get('result')
if not result:
    print(f"[ERROR] circuit {cid}: missing result in RPC response")
    sys.exit(1)

active = result.get('active_version')
supported = result.get('supported_versions') or []

if active != expected_active:
    print(f"[ERROR] circuit {cid}: active_version={active} expected={expected_active}")
    sys.exit(1)

missing = [v for v in required if v not in supported]
if missing:
  print(f"[ERROR] circuit {cid}: missing required versions {missing}; supported={supported}")
    sys.exit(1)

if strict:
    if sorted(supported) != sorted(required):
    print(f"[ERROR] circuit {cid}: strict=true and supported={supported} != required={required}")
        sys.exit(1)

print(f"[OK] circuit {cid}: active={active} supported={supported}")
PY

done

log "✅ VK window is valid for all 4 circuits"
