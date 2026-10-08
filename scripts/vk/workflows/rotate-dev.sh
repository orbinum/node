#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# scripts/vk/workflows/rotate-dev.sh
# DEV on-chain VK rotation for the spend circuits (transfer, unshield).
#
# The spec-16 v1 → v2 rotation is done by Root after `setCode`, with services
# stopped (docs/DEPLOYMENT_FLOW.md, runbook D): the calls below, in this order.
#
# Flow:
#   1) check the new keys: arity (memo-bound, or cross-tree for a transfer),
#      hash ≠ old version's, and equal to the manifest's vk_hash when a manifest
#      is given
#   2) register NEW_VERSION and make it active (one tx for both circuits) —
#      skipped for a circuit that already has it, so a failed run can be repeated
#   3) retire OLD_VERSION right away (unless --keep-old)
#   4) optional: remove OLD_VERSION (--remove-old)
#   5) check the final state: active = NEW, supported = [NEW] (or [OLD,NEW]
#      with --keep-old), on-chain hashes = the new keys'
#
# Retiring is the default: the submitter picks the version a spend is verified
# under, so while an older key is live a copier can resubmit a spend under it.
# A v1 key binds neither the memos nor the full recipient.
#
# USAGE:
#   bash scripts/vk/workflows/rotate-dev.sh [flags] <new_version> [rpc_ws] [sudo_seed] [old_version]
#
# FLAGS:
#   --keep-old          leave old_version live
#   --remove-old        also remove old_version at the end
#   --manifest <path>   circuits manifest.json to check the keys' vk_hash against
#   --circuits <list>   circuits to rotate, comma-separated (default transfer,unshield);
#                       e.g. `--circuits transfer 3 ws://... //Alice 2` for transfer v3
#
# Keys are read from artifacts/verification_key_<circuit>_v<new_version>.json
# (override the directory with VK_ARTIFACTS_DIR).
# ============================================================================

err() {
  echo "[ERROR] $*" >&2
  exit 1
}

log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

REMOVE_OLD=false
KEEP_OLD=false
MANIFEST=""
CIRCUITS="transfer unshield"
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove-old) REMOVE_OLD=true; shift ;;
    --keep-old) KEEP_OLD=true; shift ;;
    --manifest) MANIFEST="${2:-}"; [[ -f "$MANIFEST" ]] || err "--manifest needs a file"; shift 2 ;;
    --circuits) CIRCUITS="${2//,/ }"; shift 2 ;;
    --*) err "unknown flag $1" ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
if [[ "$KEEP_OLD" == true && "$REMOVE_OLD" == true ]]; then
  err "--keep-old and --remove-old are exclusive"
fi

NEW_VERSION="${POSITIONAL[0]:-}"
RPC_WS="${POSITIONAL[1]:-ws://127.0.0.1:9944}"
SUDO_SEED="${POSITIONAL[2]:-//Alice}"
OLD_VERSION="${POSITIONAL[3]:-1}"

[[ -n "$NEW_VERSION" ]] || err "Missing <new_version>. Usage: bash scripts/vk/workflows/rotate-dev.sh [flags] <new_version> [rpc_ws] [sudo_seed] [old_version]"
[[ "$NEW_VERSION" =~ ^[0-9]+$ ]] || err "new_version must be an integer >= 0"
[[ "$OLD_VERSION" =~ ^[0-9]+$ ]] || err "old_version must be an integer >= 0"
[[ "$NEW_VERSION" != "$OLD_VERSION" ]] || err "new_version and old_version cannot be equal"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VK_REGISTRY_SCRIPT="$SCRIPT_DIR/../lib/registry.sh"
ARTIFACTS_DIR="${VK_ARTIFACTS_DIR:-$NODE_DIR/artifacts}"
PACK_VERIFYING_KEY_BIN="$NODE_DIR/../groth16-proofs/target/release/pack-verifying-key"

RPC_HTTP="${RPC_WS/ws:\/\//http://}"
RPC_HTTP="${RPC_HTTP/wss:\/\//https://}"

if [[ ! -x "$PACK_VERIFYING_KEY_BIN" ]]; then
  log "Building pack-verifying-key..."
  (cd "$NODE_DIR/../groth16-proofs" && cargo build --bin pack-verifying-key --release --quiet) \
    || err "Failed to build pack-verifying-key. Run: cd groth16-proofs && cargo build --bin pack-verifying-key --release"
fi

rpc() {
  curl -s -H "Content-Type: application/json" \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":[$2]}" "$RPC_HTTP"
}

# Pack a JSON key and print the .bin path.
pack_verifying_key() {
  local json_path="$1"
  local bin_path="${json_path%.json}.bin"
  "$PACK_VERIFYING_KEY_BIN" "$json_path" "$bin_path" >/dev/null 2>&1 \
    || err "Failed to convert $(basename "$json_path") to binary"
  echo "$bin_path"
}

blake2() {
  python3 -c 'import hashlib,sys; print(hashlib.blake2b(open(sys.argv[1],"rb").read(),digest_size=32).hexdigest())' "$1"
}

# The on-chain vk_hash of (circuit, version), empty when absent.
chain_hash() {
  rpc zkVerifier_getCircuitVersionInfo "$1" | python3 -c '
import json,sys
v=int(sys.argv[1]); r=(json.load(sys.stdin).get("result") or {})
print(next((h["vk_hash"].removeprefix("0x") for h in r.get("vk_hashes",[]) if h["version"]==v), ""))' "$2"
}

CID_transfer=1
CID_unshield=2
for circuit in $CIRCUITS; do
  [[ "$circuit" == transfer || "$circuit" == unshield ]] || err "unknown circuit $circuit"
done

# Public inputs a version past 1 may have: memo-bound (base 7 + memo_hash), or
# for a transfer also cross-tree (+ a second root). The runtime refuses anything
# else, but failing here names the file.
accepted_arity() {
  case "$1" in
    transfer) echo "8 9" ;;
    unshield) echo "8" ;;
  esac
}

# ── 1. check the new keys ────────────────────────────────────────────────────
for circuit in $CIRCUITS; do
  json="$ARTIFACTS_DIR/verification_key_${circuit}_v${NEW_VERSION}.json"
  [[ -f "$json" ]] || err "missing $json"
  n_public=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["nPublic"])' "$json")
  if [[ "$NEW_VERSION" != 1 && " $(accepted_arity "$circuit") " != *" $n_public "* ]]; then
    err "$circuit v$NEW_VERSION has nPublic=$n_public; expected one of: $(accepted_arity "$circuit")"
  fi
  bin=$(pack_verifying_key "$json")
  eval "BIN_$circuit=\"\$bin\""
  eval "HASH_$circuit=\"$(blake2 "$bin")\""
  hash_var="HASH_$circuit"
  if [[ -n "$MANIFEST" ]]; then
    expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["circuits"][sys.argv[2]]["versions"][sys.argv[3]]["vk_hash"].removeprefix("0x"))' "$MANIFEST" "$circuit" "$NEW_VERSION")
    [[ "${!hash_var}" == "$expected" ]] || err "$circuit: key hash ${!hash_var} != manifest $expected"
  fi
done

for circuit in $CIRCUITS; do
  cid_var="CID_$circuit"
  hash_var="HASH_$circuit"
  old=$(chain_hash "${!cid_var}" "$OLD_VERSION")
  [[ "${!hash_var}" != "$old" ]] || err "$circuit: the new key is the old version's key"
done

CIDS=""
for circuit in $CIRCUITS; do
  cid_var="CID_$circuit"
  CIDS="$CIDS ${!cid_var}"
done

log "RPC: $RPC_WS | circuits: $CIRCUITS | old v$OLD_VERSION → new v$NEW_VERSION | keep_old=$KEEP_OLD remove_old=$REMOVE_OLD"

# ── 2. register + activate (skipped when already there) ──────────────────────
if [[ "$CIRCUITS" == "transfer unshield" \
  && -z "$(chain_hash 1 "$NEW_VERSION")" && -z "$(chain_hash 2 "$NEW_VERSION")" ]]; then
  log "Batch registering + activating both circuits (v$NEW_VERSION)..."
  bash "$VK_REGISTRY_SCRIPT" batch-register "$NEW_VERSION" 1 \
    "$BIN_transfer" "$BIN_unshield" "$RPC_WS" "$SUDO_SEED"
else
  for circuit in $CIRCUITS; do
    cid_var="CID_$circuit"
    bin_var="BIN_$circuit"
    hash_var="HASH_$circuit"
    existing=$(chain_hash "${!cid_var}" "$NEW_VERSION")
    if [[ -z "$existing" ]]; then
      log "[$circuit] register v$NEW_VERSION"
      bash "$VK_REGISTRY_SCRIPT" register "${!cid_var}" "$NEW_VERSION" "${!bin_var}" "$RPC_WS" "$SUDO_SEED"
    else
      [[ "$existing" == "${!hash_var}" ]] || err "$circuit v$NEW_VERSION is already registered with a different key"
    fi
    log "[$circuit] make v$NEW_VERSION active"
    bash "$VK_REGISTRY_SCRIPT" set-active "${!cid_var}" "$NEW_VERSION" "$RPC_WS" "$SUDO_SEED"
  done
fi

# ── 3–4. retire / remove the old version ────────────────────────────────────
supported_has() {
  rpc zkVerifier_getCircuitVersionInfo "$1" | python3 -c '
import json,sys
r=(json.load(sys.stdin).get("result") or {}); print(int(sys.argv[1]) in (r.get("supported_versions") or []))' "$2"
}
if [[ "$KEEP_OLD" != true ]]; then
  for cid in $CIDS; do
    if [[ "$(supported_has "$cid" "$OLD_VERSION")" == True ]]; then
      log "[circuit $cid] retire v$OLD_VERSION"
      bash "$VK_REGISTRY_SCRIPT" retire "$cid" "$OLD_VERSION" "$RPC_WS" "$SUDO_SEED"
    fi
  done
fi
if [[ "$REMOVE_OLD" == true ]]; then
  for cid in $CIDS; do
    if [[ -n "$(chain_hash "$cid" "$OLD_VERSION")" ]]; then
      log "[circuit $cid] remove v$OLD_VERSION"
      bash "$VK_REGISTRY_SCRIPT" remove "$cid" "$OLD_VERSION" "$RPC_WS" "$SUDO_SEED"
    fi
  done
fi

# ── 5. final state ───────────────────────────────────────────────────────────
for circuit in $CIRCUITS; do
  cid_var="CID_$circuit"
  cid="${!cid_var}"
  info=$(rpc zkVerifier_getCircuitVersionInfo "$cid")
  python3 - "$info" "$NEW_VERSION" "$OLD_VERSION" "$KEEP_OLD" "$circuit" <<'PY' || err "$circuit: final state check failed"
import json, sys
info, new, old, keep, name = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4] == "true", sys.argv[5]
r = json.loads(info).get("result") or {}
active, supported = r.get("active_version"), sorted(r.get("supported_versions") or [])
want = sorted({new, old}) if keep else [new]
if active != new or supported != want:
    sys.exit(f"[ERROR] {name}: active={active} supported={supported}, expected active={new} supported={want}")
print(f"[OK] {name}: active={active} supported={supported}")
PY
  hash_var="HASH_$circuit"
  [[ "$(chain_hash "$cid" "$NEW_VERSION")" == "${!hash_var}" ]] || err "$circuit: on-chain v$NEW_VERSION hash differs"
done

for circuit in $CIRCUITS; do
  bin_var="BIN_$circuit"
  rm -f "${!bin_var}"
done
log "✅ VK rotation completed"
