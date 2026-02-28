#!/bin/bash
#
# Sync Circuit Verification Keys Script
#
# Descarga los verification keys del último release del repositorio orbinum/circuits
# y regenera los archivos Rust en primitives/zk-verifier.
#
# Uso:
#   ./scripts/sync-circuit-artifacts.sh           # última versión (automático)
#   ./scripts/sync-circuit-artifacts.sh v0.3.1    # versión específica
#
set -e
# ============================================================================
# Configuration
# ============================================================================
CIRCUITS_REPO="orbinum/circuits"
CIRCUITS_API="https://api.github.com/repos/${CIRCUITS_REPO}/releases/latest"
# Directorios
WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VK_DIR="${WORKSPACE_ROOT}/primitives/zk-verifier/src/infrastructure/storage/verification_keys"
TEMP_DIR="${WORKSPACE_ROOT}/tmp/circuit-vkeys"
# Circuitos esperados
CIRCUITS=("disclosure" "transfer" "unshield")
# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
# ============================================================================
# Step 1: Resolver versión
# ============================================================================
log_info "════════════════════════════════════════════════════════════════"
log_info "  Sync Circuit Verification Keys"
log_info "════════════════════════════════════════════════════════════════"
if [ -n "$1" ]; then
    VERSION="$1"
    log_info "Versión especificada: ${VERSION}"
else
    log_info "Consultando última versión desde GitHub API..."
    VERSION="$(curl -fsSL "$CIRCUITS_API" | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")"
    if [ -z "$VERSION" ]; then
        log_error "No se pudo obtener la última versión desde ${CIRCUITS_API}"
        exit 1
    fi
    log_info "Última versión detectada: ${VERSION}"
fi
TARBALL_NAME="orbinum-verification-keys-${VERSION}.tar.gz"
TARBALL_URL="https://github.com/${CIRCUITS_REPO}/releases/download/${VERSION}/${TARBALL_NAME}"
# ============================================================================
# Step 2: Descargar tarball
# ============================================================================
log_info ""
log_info "Descargando verification keys..."
log_info "  URL: ${TARBALL_URL}"
mkdir -p "$TEMP_DIR"
TARBALL_PATH="${TEMP_DIR}/${TARBALL_NAME}"
if ! curl -fsSL -o "$TARBALL_PATH" "$TARBALL_URL"; then
    log_error "Error al descargar: ${TARBALL_URL}"
    exit 1
fi
log_info "  ✓ Descargado ($(du -h "$TARBALL_PATH" | cut -f1))"
# ============================================================================
# Step 3: Extraer
# ============================================================================
log_info ""
log_info "Extrayendo archivos..."
EXTRACT_DIR="${TEMP_DIR}/extracted"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$TARBALL_PATH" -C "$EXTRACT_DIR"
log_info "  ✓ Extraído en ${EXTRACT_DIR}"
# ============================================================================
# Step 4: Verificar JSON y generar Rust
# ============================================================================
log_info ""
log_info "Generando archivos Rust desde JSON..."
mkdir -p "$VK_DIR"
MISSING=()
for circuit in "${CIRCUITS[@]}"; do
    # Buscar el JSON en cualquier subnivel del tarball extraído
    VK_JSON="$(find "$EXTRACT_DIR" -name "verification_key_${circuit}.json" | head -1)"
    if [ -z "$VK_JSON" ]; then
        log_error "  ✗ verification_key_${circuit}.json no encontrado en el tarball"
        MISSING+=("verification_key_${circuit}.json")
        continue
    fi
    log_info "  verification_key_${circuit}.json ($(du -h "$VK_JSON" | cut -f1))"
    VK_RUST="${VK_DIR}/${circuit}.rs"
    if python3 "${WORKSPACE_ROOT}/scripts/generate-vk-rust.py" "$circuit" "$VK_JSON" "$VK_RUST"; then
        log_info "  ✓ Generado ${circuit}.rs"
    else
        log_error "  ✗ Falló la generación de ${circuit}.rs"
        MISSING+=("${circuit}.rs")
    fi
done
# ============================================================================
# Cleanup
# ============================================================================
rm -rf "$TEMP_DIR"
# ============================================================================
# Summary
# ============================================================================
log_info ""
log_info "════════════════════════════════════════════════════════════════"
if [ ${#MISSING[@]} -ne 0 ]; then
    log_error "❌ Archivos faltantes:"
    for f in "${MISSING[@]}"; do log_error "  - $f"; done
    exit 1
fi
log_info "✅ Verification keys sincronizadas correctamente (${VERSION})"
log_info ""
log_info "Archivos Rust generados en:"
log_info "  ${VK_DIR}/"
log_info ""
log_info "Próximos pasos:"
log_info "  1. cargo check --package orbinum-zk-verifier"
log_info "  2. git add primitives/zk-verifier/src/infrastructure/storage/verification_keys/"
log_info "     git commit -m \"chore: sync vk to ${VERSION}\""
log_info "════════════════════════════════════════════════════════════════"
