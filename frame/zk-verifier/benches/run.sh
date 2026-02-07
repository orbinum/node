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
# Criterion Benchmarks (Development - Off-chain)
# ============================================================================

run_criterion_fast() {
    print_header "Criterion Benchmarks: Fast (Development)"
    print_info "Configuration: 10 samples, 2s measurement"

    cd "$PROJECT_ROOT"
    export CRITERION_CONFIG=fast
    cargo bench --package "$PALLET_NAME" --bench groth16_verify

    print_success "Benchmarks completed"
    print_info "View results: ./benches/run.sh report"
}

run_criterion_standard() {
    print_header "Criterion Benchmarks: Standard"
    print_info "Configuration: 100 samples, 10s measurement"

    cd "$PROJECT_ROOT"
    export CRITERION_CONFIG=standard
    cargo bench --package "$PALLET_NAME" --bench groth16_verify

    print_success "Benchmarks completed"
    print_info "View results: ./benches/run.sh report"
}

run_criterion_production() {
    print_header "Criterion Benchmarks: Production (Accuracy)"
    print_info "Configuration: 200 samples, 30s measurement"
    print_warning "This process may take 10-15 minutes"

    cd "$PROJECT_ROOT"
    export CRITERION_CONFIG=production
    cargo bench --package "$PALLET_NAME" --bench groth16_verify

    print_success "Benchmarks completed"
    print_info "View results: ./benches/run.sh report"
}

# ============================================================================
# FRAME Benchmarks (Production - On-chain Weights)
# ============================================================================

run_frame_benchmarks() {
    print_header "FRAME Benchmarks: Generating Weights (Production)"
    print_warning "IMPORTANT: Run on reference hardware, NOT on laptop"
    print_info "These benchmarks generate weights to calculate on-chain fees"

    cd "$PROJECT_ROOT"

    # Verify we're in the correct directory
    if [ ! -f "Cargo.toml" ]; then
        print_error "Cargo.toml not found. Run from frame/zk-verifier/"
    fi

    # 1. Build with runtime-benchmarks
    print_info "Step 1/2: Building with runtime-benchmarks feature..."
    cargo build --release --features runtime-benchmarks

    if [ ! -f "../../../target/release/orbinum-node" ]; then
        print_error "orbinum-node binary not found"
    fi

    # 2. Run FRAME benchmarks
    print_info "Step 2/2: Running FRAME benchmarks..."

    ../../../target/release/orbinum-node benchmark pallet \
        --chain dev \
        --pallet "$PALLET_NAME" \
        --extrinsic '*' \
        --steps 50 \
        --repeat 20 \
        --output src/weights.rs \
        --template ../../../scripts/frame-weight-template.hbs

    print_success "Weights generated at: src/weights.rs"
    print_warning "REVIEW generated weights before committing!"
}

# ============================================================================
# Utilities
# ============================================================================

clean_benchmarks() {
    print_header "Cleaning Benchmark Results"

    cd "$PROJECT_ROOT"

    if [ -d "$BENCHMARK_DIR" ]; then
        rm -rf "$BENCHMARK_DIR"
        print_success "Criterion results removed"
    fi

    if [ -f "src/weights.rs.bak" ]; then
        rm -f src/weights.rs.bak
        print_success "Weights backup removed"
    fi
}

open_report() {
    cd "$PROJECT_ROOT"

    if [ ! -d "$BENCHMARK_DIR" ]; then
        print_error "No results found. Run first: ./benches/run.sh criterion-standard"
    fi

    print_info "Opening HTML report..."

    if command -v open &> /dev/null; then
        # macOS
        open "$BENCHMARK_DIR/report/index.html"
    elif command -v xdg-open &> /dev/null; then
        # Linux
        xdg-open "$BENCHMARK_DIR/report/index.html"
    else
        print_info "Open manually: $BENCHMARK_DIR/report/index.html"
    fi
}

compare_baseline() {
    print_header "Comparing with Baseline"

    cd "$PROJECT_ROOT"
    cargo bench --package "$PALLET_NAME" -- --save-baseline current

    print_success "Baseline saved as 'current'"
    print_info "To compare: cargo bench -- --baseline current"
}

run_all() {
    print_header "Running All Benchmarks"

    run_criterion_standard
    echo ""

    print_info "FRAME benchmarks skipped (require reference hardware)"
    print_info "To run: ./benches/run.sh frame"
}

show_help() {
    cat << EOF
${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
  ${GREEN}Benchmark Runner - pallet-zk-verifier${NC}
${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

${YELLOW}CRITERION BENCHMARKS${NC} (Development - Cryptographic Performance)
  ${GREEN}criterion-fast${NC}      Fast (10 samples, 2s) - Development
  ${GREEN}criterion-standard${NC}  Standard (100 samples, 10s) - Regular
  ${GREEN}criterion-prod${NC}      Production (200 samples, 30s) - Accuracy

${YELLOW}FRAME BENCHMARKS${NC} (Production - Generate On-chain Weights)
  ${GREEN}frame${NC}               Generate weights.rs (reference HW only)

${YELLOW}UTILITIES${NC}
  ${GREEN}clean${NC}               Clean results
  ${GREEN}report${NC}              Open Criterion HTML report
  ${GREEN}compare${NC}             Compare with baseline
  ${GREEN}all${NC}                 Run all Criterion benchmarks

${YELLOW}EXAMPLES${NC}
  ./benches/run.sh criterion-fast    # Fast development
  ./benches/run.sh frame            # Generate weights

${YELLOW}MORE INFO${NC}
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
        print_error "Unknown command: $1"
        echo ""
        show_help
        ;;
esac
