#!/usr/bin/env bash
# =============================================================================
# generate-validator-keys.sh — Generate session keys for a single validator.
#
# Produces two keys from one mnemonic:
#   - Aura    (Sr25519)  block production / on-chain identity
#   - GRANDPA (Ed25519)  block finalization
#
# The EVM relay key is derived automatically at node startup from the Aura
# mnemonic (same BIP39 phrase, ECDSA curve). No separate EVM key is needed.
#
# Usage:
#   ./generate-validator-keys.sh --validator N
#   ./generate-validator-keys.sh --validator 4
#
# Output (keys/validator-N/):
#   aura.json     -> Sr25519 key
#   grandpa.json  -> Ed25519 key
#   summary.txt   -> Human-readable summary
#
# Requirements:
#   - orbinum-node binary: cargo build --release
#
# IMPORTANT: The keys/ directory is in .gitignore.
#            Store the secret phrases in a password manager before proceeding.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Parameters ────────────────────────────────────────────────────────────────
VALIDATOR="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --validator) VALIDATOR="$2"; shift 2 ;;
    *) echo -e "Usage: $0 [--validator N]"; exit 1 ;;
  esac
done

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$ROOT_DIR/target/release/orbinum-node"
DIR="$SCRIPT_DIR/keys/validator-$VALIDATOR"

# ── Pre-flight checks ─────────────────────────────────────────────────────────
if [[ ! -f "$BINARY" ]]; then
  echo -e "${RED}Error: binary not found at $BINARY${NC}"
  echo -e "Build it first: ${CYAN}cargo build --release${NC}"
  exit 1
fi


if [[ -d "$DIR" ]]; then
  echo -e "${YELLOW}Warning: $DIR already exists and will be overwritten.${NC}"
  read -p "Continue? [y/N] " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && echo "Cancelled." && exit 0
fi

# ── Security warning ──────────────────────────────────────────────────────────
echo -e "${YELLOW}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                 ⚠  SECURITY WARNING  ⚠                     ║"
echo "║                                                              ║"
echo "║  SAVE the secret phrase in a password manager               ║"
echo "║  (Bitwarden, 1Password, etc.) BEFORE continuing.            ║"
echo "║                                                              ║"
echo "║  NEVER commit the keys/ directory to the repository.        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Create output directory ───────────────────────────────────────────────────
rm -rf "$DIR"
mkdir -p "$DIR"

echo -e "${CYAN}${BOLD}Generating keys for Validator $VALIDATOR${NC}\n"

# ── Aura (Sr25519) — generates the mnemonic ───────────────────────────────────
echo -e "${CYAN}Aura (Sr25519) — generating mnemonic...${NC}"
"$BINARY" key generate --scheme Sr25519 --output-type json 2>/dev/null > "$DIR/aura.json"
chmod 600 "$DIR/aura.json"

MNEMONIC=$(jq -r '.secretPhrase' "$DIR/aura.json")
AURA_SEED=$(jq -r '.secretSeed'  "$DIR/aura.json")
AURA_PUB=$(jq -r '.publicKey'    "$DIR/aura.json")
AURA_SS58=$(jq -r '.ss58Address' "$DIR/aura.json")

echo -e "  publicKey: ${GREEN}${AURA_PUB}${NC}"
echo -e "  ss58:      ${AURA_SS58}"
echo ""

# ── GRANDPA (Ed25519) — same mnemonic ────────────────────────────────────────
echo -e "${CYAN}GRANDPA (Ed25519) — same mnemonic...${NC}"
"$BINARY" key inspect --scheme Ed25519 --output-type Json "$MNEMONIC" 2>/dev/null > "$DIR/grandpa.json"
chmod 600 "$DIR/grandpa.json"

GRAN_SEED=$(jq -r '.secretSeed'  "$DIR/grandpa.json")
GRAN_PUB=$(jq -r '.publicKey'    "$DIR/grandpa.json")
GRAN_SS58=$(jq -r '.ss58Address' "$DIR/grandpa.json")

echo -e "  publicKey: ${GREEN}${GRAN_PUB}${NC}"
echo -e "  ss58:      ${GRAN_SS58}"
echo ""

# ── EVM relay key (Ecdsa/secp256k1) — same mnemonic ──────────────────────────
echo -e "${CYAN}EVM relay key (Ecdsa) — same mnemonic...${NC}"
"$BINARY" key inspect --scheme Ecdsa --output-type Json "$MNEMONIC" 2>/dev/null > "$DIR/_ecdsa_tmp.json"
EVM_SEED=$(jq -r '.secretSeed' "$DIR/_ecdsa_tmp.json")
EVM_PUB=$(jq -r '.publicKey'   "$DIR/_ecdsa_tmp.json")

EVM_ADDRESS=$(python3 -c "
from eth_account import Account
acct = Account.from_key('$EVM_SEED')
print(acct.address)
")

jq --arg addr "$EVM_ADDRESS" '. + {"evmAddress": $addr}' "$DIR/_ecdsa_tmp.json" > "$DIR/evm.json"

# ── Write summary ─────────────────────────────────────────────────────────────
SUMMARY="$DIR/summary.txt"
cat > "$SUMMARY" << EOF
# Orbinum Validator $VALIDATOR — Session Keys
# ============================================
# IMPORTANT: This file contains sensitive key material.
#            Save it in a password manager and delete it after use.
#            NEVER commit it to the repository.

## Single mnemonic (base for all keys)
secretPhrase: $MNEMONIC

## Aura (Sr25519) — on-chain identity / block production
secretSeed:   $AURA_SEED
publicKey:    $AURA_PUB
ss58:         $AURA_SS58

## GRANDPA (Ed25519) — block finalization
secretSeed:   $GRAN_SEED
publicKey:    $GRAN_PUB
ss58:         $GRAN_SS58

## EVM relay key
# Derived automatically from the Aura mnemonic at node startup.
# No separate key file or insertion step required.
# The node reads the Aura keystore entry, derives an ECDSA pair from the
# same BIP39 mnemonic, and calls register_relayer automatically.

## Insert commands (run after the node is started)
# Replace http://localhost:9944 with your node's RPC URL.

curl -s -H "Content-Type: application/json" \\
  -d '{"id":1,"jsonrpc":"2.0","method":"author_insertKey","params":["aura","$MNEMONIC","$AURA_PUB"]}' \\
  http://localhost:9944

curl -s -H "Content-Type: application/json" \\
  -d '{"id":1,"jsonrpc":"2.0","method":"author_insertKey","params":["gran","$MNEMONIC","$GRAN_PUB"]}' \\
  http://localhost:9944

## Share with the Orbinum team to request approval
Aura public key: $AURA_PUB
EOF
chmod 600 "$SUMMARY"

# ── Done ──────────────────────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}✓ Validator $VALIDATOR keys generated${NC}"
echo -e "  ${DIR}/"
echo -e "    aura.json     — Sr25519"
echo -e "    grandpa.json  — Ed25519"
echo -e "    summary.txt   — Full summary + insert commands"
echo ""
echo -e "${YELLOW}${BOLD}Next steps:${NC}"
echo -e "  1. Save ${BOLD}summary.txt${NC} to your password manager"
echo -e "  2. Start the node"
echo -e "  3. Run: ${CYAN}./insert-session-keys.sh --validator $VALIDATOR --rpc http://localhost:9944${NC}"
echo -e "  4. Restart the node (EVM relay is auto-derived from your Aura key)"
echo -e "  5. Register on-chain: session.setKeys → validatorSet.registerValidator"
echo -e "  6. Send your Aura public key to the Orbinum team to request approval"
echo ""
echo -e "${RED}${BOLD}⚠ Delete summary.txt after saving it to your password manager.${NC}"
