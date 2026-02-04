#!/bin/bash
# Benchmark execution scripts for pallet-zk-verifier
#
# Usage:
#   ./benches/run.sh [command]
#
# Commands:
#   criterion-fast      - Quick Criterion benchmarks (10 samples, 2s)
#   criterion-standard  - Regular Criterion benchmarks (100 samples, 10s) [default]
#   criterion-prod      - Production Criterion benchmarks (200 samples, 30s)
#   frame              - FRAME benchmarks (generates weights.rs)
#   clean              - Clean benchmark results
#   report             - Open Criterion HTML report
#   compare            - Compare with baseline
#   all                - Run all benchmark suites

set -e

PALLET_NAME="pallet-zk-verifier"
FRAME_DIR="frame/zk-verifier"
BENCHMARK_DIR="target/criterion"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# ============================================================================
# Criterion Benchmarks (Desarrollo - Off-chain)
# ============================================================================

run_criterion_fast() {
    print_header "Criterion Benchmarks: Fast (Desarrollo)"
    print_info "Configuración: 10 samples, 2s measurement"
    
    cd "$PROJECT_ROOT"
    export CRITERION_CONFIG=fast
    cargo bench --package "$PALLET_NAME" --bench groth16_verify
    
    print_success "Benchmarks completados"
    print_info "Ver resultados: ./benches/run.sh report"
}

run_criterion_standard() {
    print_header "Criterion Benchmarks: Standard"
    print_info "Configuración: 100 samples, 10s measurement"
    
    cd "$PROJECT_ROOT"
    export CRITERION_CONFIG=standard
    cargo bench --package "$PALLET_NAME" --bench groth16_verify
    
    print_success "Benchmarks completados"
    print_info "Ver resultados: ./benches/run.sh report"
}

run_criterion_production() {
    print_header "Criterion Benchmarks: Production (Accuracy)"
    print_info "Configuración: 200 samples, 30s measurement"
    print_warning "Este proceso puede tomar 10-15 minutos"
    
    cd "$PROJECT_ROOT"
    export CRITERION_CONFIG=production
    cargo bench --package "$PALLET_NAME" --bench groth16_verify
    
    print_success "Benchmarks completados"
    print_info "Ver resultados: ./benches/run.sh report"
}

# ============================================================================
# FRAME Benchmarks (Producción - On-chain Weights)
# ============================================================================

run_frame_benchmarks() {
    print_header "FRAME Benchmarks: Generando Weights (Producción)"
    print_warning "IMPORTANTE: Ejecutar en hardware de referencia, NO en laptop"
    print_info "Estos benchmarks generan los pesos para calcular fees on-chain"
    
    cd "$PROJECT_ROOT"
    
    # Verificar que estamos en el directorio correcto
    if [ ! -f "Cargo.toml" ]; then
        print_error "No se encuentra Cargo.toml. Ejecutar desde frame/zk-verifier/"
    fi
    
    # 1. Compilar con runtime-benchmarks
    print_info "Paso 1/2: Compilando con feature runtime-benchmarks..."
    cargo build --release --features runtime-benchmarks
    
    if [ ! -f "../../../target/release/orbinum-node" ]; then
        print_error "No se encuentra el binario orbinum-node"
    fi
    
    # 2. Ejecutar benchmarks FRAME
    print_info "Paso 2/2: Ejecutando FRAME benchmarks..."
    
    ../../../target/release/orbinum-node benchmark pallet \
        --chain dev \
        --pallet "$PALLET_NAME" \
        --extrinsic '*' \
        --steps 50 \
        --repeat 20 \
        --output src/weights.rs \
        --template ../../../scripts/frame-weight-template.hbs
    
    print_success "Weights generados en: src/weights.rs"
    print_warning "REVISAR los pesos generados antes de commit!"
}

# ============================================================================
# Utilidades
# ============================================================================

clean_benchmarks() {
    print_header "Limpiando Resultados de Benchmarks"
    
    cd "$PROJECT_ROOT"
    
    if [ -d "$BENCHMARK_DIR" ]; then
        rm -rf "$BENCHMARK_DIR"
        print_success "Resultados Criterion eliminados"
    fi
    
    if [ -f "src/weights.rs.bak" ]; then
        rm -f src/weights.rs.bak
        print_success "Backup de weights eliminado"
    fi
}

open_report() {
    cd "$PROJECT_ROOT"
    
    if [ ! -d "$BENCHMARK_DIR" ]; then
        print_error "No hay resultados. Ejecutar primero: ./benches/run.sh criterion-standard"
    fi
    
    print_info "Abriendo reporte HTML..."
    
    if command -v open &> /dev/null; then
        # macOS
        open "$BENCHMARK_DIR/report/index.html"
    elif command -v xdg-open &> /dev/null; then
        # Linux
        xdg-open "$BENCHMARK_DIR/report/index.html"
    else
        print_info "Abrir manualmente: $BENCHMARK_DIR/report/index.html"
    fi
}

compare_baseline() {
    print_header "Comparando con Baseline"
    
    cd "$PROJECT_ROOT"
    cargo bench --package "$PALLET_NAME" -- --save-baseline current
    
    print_success "Baseline guardado como 'current'"
    print_info "Para comparar: cargo bench -- --baseline current"
}

run_all() {
    print_header "Ejecutando Todos los Benchmarks"
    
    run_criterion_standard
    echo ""
    
    print_info "FRAME benchmarks omitidos (requieren hardware de referencia)"
    print_info "Para ejecutar: ./benches/run.sh frame"
}

show_help() {
    cat << EOF
${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
  ${GREEN}Benchmark Runner - pallet-zk-verifier${NC}
${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

${YELLOW}CRITERION BENCHMARKS${NC} (Desarrollo - Performance Criptográfica)
  ${GREEN}criterion-fast${NC}      Rápido (10 samples, 2s) - Desarrollo
  ${GREEN}criterion-standard${NC}  Estándar (100 samples, 10s) - Regular
  ${GREEN}criterion-prod${NC}      Producción (200 samples, 30s) - Accuracy

${YELLOW}FRAME BENCHMARKS${NC} (Producción - Generar Weights On-chain)
  ${GREEN}frame${NC}               Generar weights.rs (solo en HW referencia)

${YELLOW}UTILIDADES${NC}
  ${GREEN}clean${NC}               Limpiar resultados
  ${GREEN}report${NC}              Abrir reporte HTML Criterion
  ${GREEN}compare${NC}             Comparar con baseline
  ${GREEN}all${NC}                 Ejecutar todos los Criterion benchmarks

${YELLOW}EJEMPLOS${NC}
  ./benches/run.sh criterion-fast    # Desarrollo rápido
  ./benches/run.sh frame            # Generar weights

${YELLOW}MÁS INFO${NC}
  benches/README.md
EOF
}

# ============================================================================
# Main
# ============================================================================

case "${1:-criterion-standard}" in
    criterion-fast)
        run_criterion_fast
        ;;
    criterion-standard|standard)
        run_criterion_standard
        ;;
    criterion-prod|production)
        run_criterion_production
        ;;
    frame)
        run_frame_benchmarks
        ;;
    clean)
        clean_benchmarks
        ;;
    report)
        open_report
        ;;
    compare)
        compare_baseline
        ;;
    all)
        run_all
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Comando desconocido: $1"
        echo ""
        show_help
        ;;
esac
