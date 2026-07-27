#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Orbinum Testnet Chain Spec Generator ===${NC}\n"

# Resolve script location so all relative paths work regardless of cwd.
# Script lives in scripts/generate-specs/, so the repo root is two levels up.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# The release binary is required: the WASM it embeds becomes the genesis `:code`,
# so a debug build would produce a different genesis hash than the one nodes run.
BINARY="$NODE_ROOT/target/release/orbinum-node"
if [ ! -f "$BINARY" ]; then
    echo -e "${YELLOW}Release binary not found. Building...${NC}"
    (cd "$NODE_ROOT" && cargo build --release --package orbinum-node)
    echo -e "${GREEN}✓ Build complete${NC}\n"
fi

# Output goes to scripts/generate-specs/dist/ (gitignored). The generated spec
# is NOT consumed from here — copy it into the node-deploy repo (see final step).
DEPLOY_DIR="$SCRIPT_DIR/dist"
mkdir -p "$DEPLOY_DIR"

echo -e "${YELLOW}Step 1: Generating plain chain spec from 'testnet' config${NC}"
$BINARY build-spec --chain testnet --disable-default-bootnode > "$DEPLOY_DIR/testnet-spec-plain.json"
echo -e "${GREEN}✓ Plain spec generated: testnet-spec-plain.json${NC}\n"

echo -e "${YELLOW}Step 2: Customizing chain spec${NC}"

cat "$DEPLOY_DIR/testnet-spec-plain.json" | jq '
  .name = "Orbinum Testnet" |
  .id = "orbinum_testnet" |
  .chainType = "Live" |
  .protocolId = "orbinum" |
  .properties.tokenSymbol = "ORB" |
  .properties.tokenDecimals = 18 |
  .bootNodes = [
    "/dns/rpc-1.testnet.orbinum.io/tcp/30333/p2p/12D3KooWBzqb1AFLQJd4NooU7q6dSsYBFL85A8RPsJDLesfxHvbW",
    "/dns/rpc-2.testnet.orbinum.io/tcp/30333/p2p/12D3KooWKiLEh2Z8XZYGejL5ZMR6rwEdZHPTpVDW3nsXfSW8paLt"
  ] |
  .telemetryEndpoints = [
    ["/dns4/telemetry.polkadot.io/tcp/443/x-parity-wss/%2Fsubmit%2F", 0]
  ]
' > "$DEPLOY_DIR/testnet-spec-customized.json"
echo -e "${GREEN}✓ Chain spec customized${NC}\n"

echo -e "${YELLOW}Step 3: Converting to raw format${NC}"
$BINARY build-spec --chain "$DEPLOY_DIR/testnet-spec-customized.json" --raw --disable-default-bootnode > "$DEPLOY_DIR/testnet-spec.json"
echo -e "${GREEN}✓ Raw spec generated: testnet-spec.json${NC}\n"

# Extract genesis hash
GENESIS_HASH=$(cat "$DEPLOY_DIR/testnet-spec.json" | jq -r '.genesis.raw.top."0x3a636f6465"' | head -c 66)
echo -e "${GREEN}Genesis Hash: ${GENESIS_HASH}${NC}"

# Clean up intermediate files
rm -f "$DEPLOY_DIR/testnet-spec-plain.json" "$DEPLOY_DIR/testnet-spec-customized.json"

echo -e "\n${GREEN}=== Chain Spec Generation Complete ===${NC}\n"
echo -e "Generated file:"
echo -e "  ${GREEN}✓${NC} $DEPLOY_DIR/testnet-spec.json\n"

echo -e "${YELLOW}Deploy it — copy into the node-deploy repo (nodes read it from there):${NC}"
echo -e "  ${GREEN}cp \"$DEPLOY_DIR/testnet-spec.json\" /path/to/node-deploy/testnet/chainspec/testnet-spec.json${NC}"
echo -e "  ${GREEN}cd /path/to/node-deploy && git add testnet/chainspec/testnet-spec.json && git commit${NC}\n"

echo -e "${YELLOW}Notes:${NC}"
echo -e "  - Changing genesis is a NEW chain: every node must purge its DB and resync."
echo -e "  - Bootnodes are hardcoded above (rpc-1 / rpc-2)."
echo -e "  - Peer ID of a running node: ${GREEN}docker logs <container> | grep 'Local node identity'${NC}\n"
