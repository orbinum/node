#!/usr/bin/env bash

# Verify a built node targets the Hyperbridge deployment the environment expects.
#
# Usage:
#   ./scripts/verify-coprocessor.sh <testnet|mainnet> [path/to/orbinum-node]
#
# Why this exists: the coprocessor is a compile-time constant chosen by the
# `hyperbridge-testnet` feature, and getting it wrong is invisible until a relayer tries
# to work. `Polkadot(3367)` and `Kusama(4009)` are distinct SCALE variants which
# `is_allowed_proxy` compares with `==`, so a testnet chain running a mainnet-coprocessor
# runtime answers every proxied request with `RequestProxyProhibited` — after the deploy
# has already succeeded.
#
# Reading it back off the binary is the only check that cannot be self-consistently
# wrong: it asks the runtime what it was compiled with, rather than trusting that the
# right flag was passed.

set -euo pipefail

ENVIRONMENT="${1:-}"
NODE="${2:-./target/release/orbinum-node}"

# SCALE encodings of `Option<StateMachine>`: 0x01 = Some, then the variant index, then
# the u32 para id little-endian.
#   Kusama(4009)   → 01 02 a9 0f 00 00
#   Polkadot(3367) → 01 01 27 0d 00 00
case "$ENVIRONMENT" in
    testnet) EXPECTED="0x0102a90f0000"; DESC="Kusama(4009)"  ;;
    mainnet) EXPECTED="0x0101270d0000"; DESC="Polkadot(3367)";;
    *)
        echo "Usage: $0 <testnet|mainnet> [node-binary]" >&2
        exit 1
        ;;
esac

[[ -x "$NODE" ]] || { echo "Error: node binary not found at $NODE" >&2; exit 1; }

PORT="${VERIFY_PORT:-9977}"
LOG=$(mktemp)
trap 'kill $PID 2>/dev/null; rm -f "$LOG"' EXIT

"$NODE" --dev --tmp --rpc-port "$PORT" > "$LOG" 2>&1 &
PID=$!

for _ in $(seq 1 60); do
    if curl -s -m 2 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"system_chain","params":[]}' \
        "http://127.0.0.1:$PORT" 2>/dev/null | grep -q result
    then
        break
    fi
    sleep 1
done

query() {
    curl -s -m 10 -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"state_call\",\"params\":[\"$1\",\"0x\"]}" \
        "http://127.0.0.1:$PORT" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",""))'
}

ACTUAL=$(query OrbinumIsmpApi_coprocessor)
HOST=$(query IsmpRuntimeApi_host_state_machine)

echo "environment: $ENVIRONMENT"
echo "coprocessor: $ACTUAL (expected $EXPECTED = $DESC)"
echo "host:        $HOST (expected 0x036f726269 = Substrate(\"orbi\"))"

rc=0
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    echo "" >&2
    echo "ERROR: this binary is built for the wrong Hyperbridge deployment." >&2
    if [[ "$ENVIRONMENT" == "testnet" ]]; then
        echo "       Rebuild with: make build-release FEATURES=hyperbridge-testnet" >&2
    else
        echo "       Rebuild without the hyperbridge-testnet feature." >&2
    fi
    rc=1
fi

# The host id is feature-independent, but a deploy is worthless without it: it is the
# exact call Tesseract makes to derive our state machine.
if [[ "$HOST" != "0x036f726269" ]]; then
    echo "" >&2
    echo "ERROR: host_state_machine is '$HOST', not Substrate(\"orbi\")." >&2
    echo "       Tesseract derives our identity from this call and will not start." >&2
    rc=1
fi

[[ $rc -eq 0 ]] && echo "OK: binary matches the $ENVIRONMENT deployment."
exit $rc
