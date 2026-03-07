#!/bin/bash
#
# Sync Circuit Verification Keys Script
#
# Downloads verification keys from the latest release of the orbinum/circuits repository
# and regenerates Rust files in primitives/zk-verifier.
#
# Usage:
#   ./scripts/sync-circuits/sync-circuit-artifacts.sh           # latest version (automatic)
#   ./scripts/sync-circuits/sync-circuit-artifacts.sh v0.3.1    # specific version
#
set -e
# ============================================================================
# Configuration
# ============================================================================
CIRCUITS_REPO="orbinum/circuits"
CIRCUITS_API="https://api.github.com/repos/${CIRCUITS_REPO}/releases/latest"
# Directories
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VK_DIR="${WORKSPACE_ROOT}/primitives/zk-verifier/src/infrastructure/storage/verification_keys"
TEMP_DIR="${SCRIPT_DIR}/tmp"
# Expected circuits
CIRCUITS=("disclosure" "transfer" "unshield" "private_link")
# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT
# ============================================================================
# Step 1: Resolve version
# ============================================================================
log_info "════════════════════════════════════════════════════════════════"
log_info "  Sync Circuit Verification Keys"
log_info "════════════════════════════════════════════════════════════════"
if [ -n "$1" ]; then
    VERSION="$1"
    log_info "Specified version: ${VERSION}"
else
    log_info "Fetching latest version from GitHub API..."
    VERSION="$(curl -fsSL "$CIRCUITS_API" | jq -r '.tag_name')"
    if [ -z "$VERSION" ]; then
        log_error "Failed to fetch latest version from ${CIRCUITS_API}"
        exit 1
    fi
    log_info "Latest version detected: ${VERSION}"
fi
TARBALL_NAME="orbinum-verification-keys-${VERSION}.tar.gz"
TARBALL_URL="https://github.com/${CIRCUITS_REPO}/releases/download/${VERSION}/${TARBALL_NAME}"
# ============================================================================
# Step 2: Download tarball
# ============================================================================
log_info ""
log_info "Downloading verification keys..."
log_info "  URL: ${TARBALL_URL}"
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
TARBALL_PATH="${TEMP_DIR}/${TARBALL_NAME}"
if ! curl -fsSL -o "$TARBALL_PATH" "$TARBALL_URL"; then
    log_error "Download failed: ${TARBALL_URL}"
    exit 1
fi
log_info "  ✓ Downloaded ($(du -h "$TARBALL_PATH" | cut -f1))"
# ============================================================================
# Step 3: Extract
# ============================================================================
log_info ""
log_info "Extracting files..."
EXTRACT_DIR="${TEMP_DIR}/extracted"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$TARBALL_PATH" -C "$EXTRACT_DIR"
log_info "  ✓ Extracted to ${EXTRACT_DIR}"
# ============================================================================
# Step 4: Verify JSON and generate Rust
# ============================================================================
log_info ""
log_info "Generating Rust files from JSON..."
mkdir -p "$VK_DIR"
MISSING=()
for circuit in "${CIRCUITS[@]}"; do
    # Search for JSON at any sublevel of the extracted tarball
    VK_JSON="$(find "$EXTRACT_DIR" -name "verification_key_${circuit}.json" | head -1)"
    if [ -z "$VK_JSON" ]; then
        log_error "  ✗ verification_key_${circuit}.json not found in tarball"
        MISSING+=("verification_key_${circuit}.json")
        continue
    fi
    log_info "  verification_key_${circuit}.json ($(du -h "$VK_JSON" | cut -f1))"
    VK_RUST="${VK_DIR}/${circuit}.rs"
    if bash "${WORKSPACE_ROOT}/scripts/sync-circuits/generate-vk-rust.sh" "$circuit" "$VK_JSON" "$VK_RUST"; then
        log_info "  ✓ Generated ${circuit}.rs"
    else
        log_error "  ✗ Failed to generate ${circuit}.rs"
        MISSING+=("${circuit}.rs")
    fi
done
# ============================================================================
# Summary
# ============================================================================
log_info ""
log_info "════════════════════════════════════════════════════════════════"
if [ ${#MISSING[@]} -ne 0 ]; then
    log_error "❌ Missing files:"
    for f in "${MISSING[@]}"; do log_error "  - $f"; done
    exit 1
fi
log_info "✅ Verification keys synchronized successfully (${VERSION})"
log_info ""
log_info "Rust files generated in:"
log_info "  ${VK_DIR}/"
log_info ""
log_info "Next steps:"
log_info "  1. cargo check --package orbinum-zk-verifier"
log_info "  2. git add primitives/zk-verifier/src/infrastructure/storage/verification_keys/"
log_info "     git commit -m \"chore: sync vk to ${VERSION}\""
log_info "════════════════════════════════════════════════════════════════"
