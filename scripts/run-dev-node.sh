#!/usr/bin/env bash
# =============================================================================
# Orbinum Development Node Runner
# =============================================================================
# This script runs the Orbinum node in development mode with automatic
# block production and temporary storage.
#
# Usage:
#   ./scripts/run-dev-node.sh              # Run with default settings
#   ./scripts/run-dev-node.sh --manual     # Enable manual seal (for testing)
#   ./scripts/run-dev-node.sh --persist    # Use persistent storage
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              ORBINUM DEVELOPMENT NODE                          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"

# Parse arguments
MANUAL_SEAL=""
TMP_FLAG="--tmp"
DATA_PATH=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --manual)
            MANUAL_SEAL="--sealing=manual"
            echo -e "${YELLOW}Manual seal mode enabled${NC}"
            shift
            ;;
        --persist)
            TMP_FLAG=""
            DATA_PATH="--base-path ${PROJECT_ROOT}/data/dev"
            echo -e "${YELLOW}Persistent storage mode enabled${NC}"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Build if needed
if [ ! -f "$PROJECT_ROOT/target/release/orbinum-node" ]; then
    echo -e "${YELLOW}Building node in release mode...${NC}"
    cd "$PROJECT_ROOT"
    cargo build --release --package=orbinum-node
fi

echo ""
echo -e "${GREEN}Starting Orbinum development node...${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  RPC:       ${GREEN}http://127.0.0.1:9944${NC}"
echo -e "  WS:        ${GREEN}ws://127.0.0.1:9944${NC}"
echo -e "  Ethereum:  ${GREEN}http://127.0.0.1:9944${NC} (EVM JSON-RPC)"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Pre-funded accounts (Ethereum compatible):${NC}"
echo -e "  Alith:     ${GREEN}0xf24FF3a9CF04c71Dbc94D0b566f7A27B94566cac${NC}"
echo -e "  Baltathar: ${GREEN}0x3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0${NC}"
echo -e "  Charleth:  ${GREEN}0x798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc${NC}"
echo ""
echo -e "${YELLOW}Dev account private keys (for testing only):${NC}"
echo -e "  Alith:     ${GREEN}0x5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133${NC}"
echo ""
echo -e "${BLUE}Press Ctrl+C to stop the node${NC}"
echo ""

# Run the node
cd "$PROJECT_ROOT"
./target/release/orbinum-node \
    --dev \
    $TMP_FLAG \
    $DATA_PATH \
    $MANUAL_SEAL \
    --rpc-external \
    --rpc-cors=all \
    --rpc-methods=unsafe \
    -linfo,evm=debug,runtime::zk-verifier=debug,runtime::shielded-pool=debug
