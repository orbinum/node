#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Orbinum Testnet Chain Spec Generator ===${NC}\n"

# Resolve script location so all relative paths work regardless of cwd
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Prefer release binary; fall back to debug; build if neither exists
if [ -f "$NODE_ROOT/target/release/orbinum-node" ]; then
    BINARY="$NODE_ROOT/target/release/orbinum-node"
elif [ -f "$NODE_ROOT/target/debug/orbinum-node" ]; then
    echo -e "${YELLOW}Release binary not found, using debug build.${NC}"
    BINARY="$NODE_ROOT/target/debug/orbinum-node"
else
    echo -e "${YELLOW}No binary found. Building (debug)...${NC}"
    (cd "$NODE_ROOT" && cargo build --package orbinum-node)
    BINARY="$NODE_ROOT/target/debug/orbinum-node"
    echo -e "${GREEN}✓ Build complete${NC}\n"
fi

DEPLOY_DIR="$SCRIPT_DIR"

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
  .telemetryEndpoints = [["wss://telemetry.polkadot.io/submit/", 0]] |
  .bootNodes = [
    "/dns/rpc-1.testnet.orbinum.io/tcp/30333/p2p/12D3KooWBzqb1AFLQJd4NooU7q6dSsYBFL85A8RPsJDLesfxHvbW",
    "/dns/rpc-2.testnet.orbinum.io/tcp/30333/p2p/12D3KooWKiLEh2Z8XZYGejL5ZMR6rwEdZHPTpVDW3nsXfSW8paLt"
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
echo -e "Generated files:"
echo -e "  ${GREEN}✓${NC} deploy/testnet-spec.json (Use this for your nodes)\n"

echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Share testnet-spec.json with all testnet participants"
echo -e "2. Generate validator keys: ${GREEN}$BINARY key generate${NC}"
echo -e "3. Start your node: ${GREEN}docker-compose up -d${NC}"
echo -e "4. Add boot nodes to testnet-spec.json after first nodes are running\n"

echo -e "${YELLOW}To get your node's Peer ID:${NC}"
echo -e "  ${GREEN}docker-compose logs | grep 'Local node identity'${NC}\n"
