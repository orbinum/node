#!/usr/bin/env bash
# Boots a dev node, runs an ISMP suite against it, tears the node down.
#
#   ./scripts/run-ismp-tests.sh              # both suites
#   ./scripts/run-ismp-tests.sh e2e          # functional only
#   ./scripts/run-ismp-tests.sh security     # adversarial only
#
# Requires `npm install` in scripts/ and one of:
#   cargo build --release -p orbinum-node                              # mainnet target
#   cargo build --release -p orbinum-node --features hyperbridge-testnet # Paseo target
#
# The suites are NOT target-agnostic. Which Hyperbridge deployment the runtime points
# at decides the relay variant of every whitelist key, so the suites read it off the
# node via `OrbinumIsmpApi_coprocessor` and derive their expectations from it. They
# previously hardcoded `Polkadot(4009)` and passed against a `hyperbridge-testnet` build
# that tracks `Kusama(4009)` — wrong key, wrong read-back, green suite.
#
# Point ISMP_NODE_BIN at a Paseo build to exercise that target:
#   cargo build --release -p orbinum-node --features hyperbridge-testnet --target-dir target/paseo
#   ISMP_NODE_BIN=target/paseo/release/orbinum-node ./scripts/run-ismp-tests.sh all
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SUITE="${1:-all}"
PORT="${ISMP_TEST_PORT:-9955}"
NODE_LOG="${TMPDIR:-/tmp}/orbinum-ismp-node.log"
NODE_BIN="${ISMP_NODE_BIN:-./target/release/orbinum-node}"

[[ -x "$NODE_BIN" ]] || { echo "missing $NODE_BIN — run: cargo build --release -p orbinum-node"; exit 1; }

"$NODE_BIN" --dev --tmp --rpc-port "$PORT" > "$NODE_LOG" 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null; wait $NODE_PID 2>/dev/null' EXIT

# Wait on the RPC answering rather than a fixed sleep — the node is ready when it
# says so, and a fixed delay is either wasteful or flaky depending on the machine.
for i in $(seq 1 60); do
  curl -s -m 2 -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"system_chain","params":[]}' \
    "http://127.0.0.1:$PORT" 2>/dev/null | grep -q result && { echo "node up after ${i}s"; break; }
  sleep 1
done

# Extrinsics are not included until a block exists.
for i in $(seq 1 30); do
  grep -q "Imported #1" "$NODE_LOG" 2>/dev/null && { echo "block 1 produced"; break; }
  sleep 1
done

RC=0
run_suite() {
  node "scripts/$1" "ws://127.0.0.1:$PORT" || RC=1
}

case "$SUITE" in
  e2e)      run_suite test-ismp-e2e.mjs ;;
  security) run_suite test-ismp-security.mjs ;;
  all)      run_suite test-ismp-e2e.mjs; run_suite test-ismp-security.mjs ;;
  *)        echo "unknown suite '$SUITE' (expected: e2e | security | all)"; exit 2 ;;
esac

# A runtime panic is a finding even when every assertion passed, so the node log is
# checked independently of the suite's own result.
if grep -qiE "panicked at|Runtime panic|Essential task .* failed|CoprocessorNotSet" "$NODE_LOG"; then
  echo ""
  echo "!! RUNTIME PANIC IN NODE LOG:"
  grep -iE "panicked at|Runtime panic|Essential task .* failed" "$NODE_LOG" | head -5
  RC=1
fi

exit $RC
