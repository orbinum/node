#!/bin/bash
#
# Sync Circuit Artifacts Script
# 
# Downloads circuit artifacts tarball from circuits repository release
# and extracts to artifacts/ directory in workspace root.
#
# Usage:
#   ./scripts/sync-circuit-artifacts.sh [VERSION]
#
# Example:
#   ./scripts/sync-circuit-artifacts.sh v0.1.0
#
# This script:
# 1. Downloads tarball containing all circuit artifacts (WASM, ARK, ZKEY, VK)
# 2. Extracts to artifacts/ directory in workspace root
# 3. Verifies all expected files are present
#

set -e

# ============================================================================
# Configuration
# ============================================================================

CIRCUITS_VERSION="${1:-v0.1.0}"
CIRCUITS_REPO="orbinum/circuits"
TARBALL_NAME="orbinum-circuits-${CIRCUITS_VERSION}.tar.gz"
TARBALL_URL="https://github.com/${CIRCUITS_REPO}/releases/download/${CIRCUITS_VERSION}/${TARBALL_NAME}"

# Directories
WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS_DIR="${WORKSPACE_ROOT}/artifacts"
ZK_VERIFIER_VK_DIR="${WORKSPACE_ROOT}/primitives/zk-verifier/src/vk"
TEMP_DIR="${WORKSPACE_ROOT}/tmp/circuit-artifacts"

# Expected circuits
CIRCUITS=("disclosure" "transfer" "unshield")

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================================================
# Main Script
# ============================================================================

log_info "════════════════════════════════════════════════════════════════"
log_info "  Circuit Artifacts Sync - Version ${CIRCUITS_VERSION}"
log_info "════════════════════════════════════════════════════════════════"

# Create directories
log_info "Creating directories..."
mkdir -p "$TEMP_DIR"
mkdir -p "$ARTIFACTS_DIR"

# ============================================================================
# Step 1: Download Tarball
# ============================================================================

log_info ""
log_info "Step 1: Downloading circuit artifacts tarball..."
log_info "────────────────────────────────────────────────────────────────"

TARBALL_PATH="${TEMP_DIR}/${TARBALL_NAME}"

log_info "Downloading: ${TARBALL_NAME}"
log_info "From: ${TARBALL_URL}"

if curl -L -f -S -o "$TARBALL_PATH" "$TARBALL_URL"; then
    log_info "  ✓ Downloaded tarball ($(du -h "$TARBALL_PATH" | cut -f1))"
else
    log_error "  ✗ Failed to download tarball"
    log_error "    URL: $TARBALL_URL"
    exit 1
fi

# ============================================================================
# Step 2: Extract Tarball
# ============================================================================

log_info ""
log_info "Step 2: Extracting tarball to artifacts/..."
log_info "────────────────────────────────────────────────────────────────"

# Extract to artifacts directory
if tar -xzf "$TARBALL_PATH" -C "$ARTIFACTS_DIR"; then
    log_info "  ✓ Extracted tarball successfully"
else
    log_error "  ✗ Failed to extract tarball"
    exit 1
fi

# ============================================================================
# Step 3: Reorganize Files
# ============================================================================

log_info ""
log_info "Step 3: Reorganizing files to artifacts root..."
log_info "────────────────────────────────────────────────────────────────"

# Move WASM files from build/*/
for circuit in "${CIRCUITS[@]}"; do
    wasm_source="${ARTIFACTS_DIR}/build/${circuit}_js/${circuit}.wasm"
    wasm_dest="${ARTIFACTS_DIR}/${circuit}.wasm"
    
    if [ -f "$wasm_source" ]; then
        mv "$wasm_source" "$wasm_dest"
        log_info "  ✓ Moved ${circuit}.wasm to root"
    else
        log_warn "  ⚠ ${circuit}.wasm not found in expected location"
    fi
done

# Move VK files from build/
for circuit in "${CIRCUITS[@]}"; do
    vk_source="${ARTIFACTS_DIR}/build/verification_key_${circuit}.json"
    vk_dest="${ARTIFACTS_DIR}/verification_key_${circuit}.json"
    
    if [ -f "$vk_source" ]; then
        mv "$vk_source" "$vk_dest"
        log_info "  ✓ Moved verification_key_${circuit}.json to root"
    else
        log_warn "  ⚠ verification_key_${circuit}.json not found in expected location"
    fi
done

# Move ARK files from keys/
for circuit in "${CIRCUITS[@]}"; do
    ark_source="${ARTIFACTS_DIR}/keys/${circuit}_pk.ark"
    ark_dest="${ARTIFACTS_DIR}/${circuit}_pk.ark"
    
    if [ -f "$ark_source" ]; then
        mv "$ark_source" "$ark_dest"
        log_info "  ✓ Moved ${circuit}_pk.ark to root"
    else
        log_warn "  ⚠ ${circuit}_pk.ark not found in expected location"
    fi
done

# Move ZKEY files from keys/ (optional)
for circuit in "${CIRCUITS[@]}"; do
    zkey_source="${ARTIFACTS_DIR}/keys/${circuit}_pk.zkey"
    zkey_dest="${ARTIFACTS_DIR}/${circuit}.zkey"
    
    if [ -f "$zkey_source" ]; then
        mv "$zkey_source" "$zkey_dest"
        log_info "  ✓ Moved ${circuit}.zkey to root"
    fi
done

# Clean up empty directories
rm -rf "${ARTIFACTS_DIR}/build" "${ARTIFACTS_DIR}/keys" "${ARTIFACTS_DIR}/release"
log_info "  ✓ Cleaned up subdirectories"

# ============================================================================
# Step 4: Generate Rust VK Files from JSON
# ============================================================================

log_info ""
log_info "Step 4: Generating Rust VK files from JSON..."
log_info "────────────────────────────────────────────────────────────────"

# Create zk-verifier VK directory if it doesn't exist
mkdir -p "$ZK_VERIFIER_VK_DIR"

# Generate Rust files from JSON
for circuit in "${CIRCUITS[@]}"; do
    vk_json="${ARTIFACTS_DIR}/verification_key_${circuit}.json"
    vk_rust="${ZK_VERIFIER_VK_DIR}/${circuit}.rs"
    
    if [ -f "$vk_json" ]; then
        if python3 "${WORKSPACE_ROOT}/scripts/generate-vk-rust.py" "$circuit" "$vk_json" "$vk_rust"; then
            log_info "  ✓ Generated ${circuit}.rs from JSON"
        else
            log_error "  ✗ Failed to generate ${circuit}.rs"
        fi
    else
        log_warn "  ⚠ verification_key_${circuit}.json not found, skipping Rust generation"
    fi
done

# ============================================================================
# Step 5: Verify Files
# ============================================================================

log_info ""
log_info "Step 5: Verifying extracted files..."
log_info "────────────────────────────────────────────────────────────────"

MISSING_FILES=()

for circuit in "${CIRCUITS[@]}"; do
    log_info "Checking circuit: $circuit"
    
    # Check WASM
    if [ -f "${ARTIFACTS_DIR}/${circuit}.wasm" ]; then
        log_info "  ✓ ${circuit}.wasm ($(du -h "${ARTIFACTS_DIR}/${circuit}.wasm" | cut -f1))"
    else
        log_error "  ✗ ${circuit}.wasm missing"
        MISSING_FILES+=("${circuit}.wasm")
    fi
    
    # Check ARK (Proving Key)
    if [ -f "${ARTIFACTS_DIR}/${circuit}_pk.ark" ]; then
        log_info "  ✓ ${circuit}_pk.ark ($(du -h "${ARTIFACTS_DIR}/${circuit}_pk.ark" | cut -f1))"
    else
        log_error "  ✗ ${circuit}_pk.ark missing"
        MISSING_FILES+=("${circuit}_pk.ark")
    fi
    
    # Check ZKEY
    if [ -f "${ARTIFACTS_DIR}/${circuit}.zkey" ]; then
        log_info "  ✓ ${circuit}.zkey ($(du -h "${ARTIFACTS_DIR}/${circuit}.zkey" | cut -f1))"
    else
        log_warn "  ⚠ ${circuit}.zkey missing (optional)"
    fi
    
    # Check VK (Verification Key)
    if [ -f "${ARTIFACTS_DIR}/verification_key_${circuit}.json" ]; then
        log_info "  ✓ verification_key_${circuit}.json ($(du -h "${ARTIFACTS_DIR}/verification_key_${circuit}.json" | cut -f1))"
    else
        log_error "  ✗ verification_key_${circuit}.json missing"
        MISSING_FILES+=("verification_key_${circuit}.json")
    fi
    
    echo ""
done

# ============================================================================
# Cleanup
# ============================================================================

log_info "Cleaning up temporary files..."
rm -rf "$TEMP_DIR"
log_info "  ✓ Removed temporary directory"

# ============================================================================
# Summary
# ============================================================================

log_info ""
log_info "════════════════════════════════════════════════════════════════"
log_info "  Summary"
log_info "════════════════════════════════════════════════════════════════"

if [ ${#MISSING_FILES[@]} -eq 0 ]; then
    log_info "✅ All artifacts synced successfully!"
    log_info ""
    log_info "Artifacts location:"
    log_info "  ${ARTIFACTS_DIR}/"
    log_info ""
    log_info "Rust VK files generated in:"
    log_info "  ${ZK_VERIFIER_VK_DIR}/"
    log_info ""
    log_info "Available files:"
    ls -lh "$ARTIFACTS_DIR" | tail -n +2 | awk '{printf "  - %-40s %s\n", $9, $5}'
    log_info ""
    log_info "Next steps:"
    log_info "  1. Test the changes:"
    log_info "     cargo test --package fp-encrypted-memo --features wasm-witness"
    log_info ""
    log_info "  2. Commit changes:"
    log_info "     git add artifacts/ primitives/zk-verifier/src/vk/"
    log_info "     git commit -m \"chore: sync circuit artifacts to ${CIRCUITS_VERSION}\""
else
    log_error "❌ Some files are missing:"
    for missing in "${MISSING_FILES[@]}"; do
        log_error "  - $missing"
    done
    log_error ""
    log_error "Check the tarball contents:"
    log_error "  ${TARBALL_URL}"
    exit 1
fi

log_info "════════════════════════════════════════════════════════════════"
