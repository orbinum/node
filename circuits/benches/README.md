# Circuit Benchmarks

Professional performance benchmarking suite for Orbinum zero-knowledge circuits.

## Overview

This directory contains TypeScript-based benchmarks for all Orbinum circuits, measuring:
- **Witness Generation**: Time and memory to prepare circuit inputs
- **Proof Generation**: Time and memory for ZK proof creation
- **Proof Verification**: Time to verify proofs
- **Throughput**: Operations per second for each operation

## Quick Start

```bash
# Run all circuit benchmarks
npm run bench

# Run specific circuit benchmarks
npm run bench:transfer
npm run bench:disclosure
```

## Prerequisites

Before running benchmarks, ensure circuits are compiled and have trusted setup completed:

```bash
# For transfer circuit
npm run full-build:transfer
npm run gen-input:transfer

# For disclosure circuit  
npm run full-build:disclosure
npm run gen-input:disclosure
```

## Benchmark Files

- **`types.ts`** - TypeScript type definitions for benchmark results
- **`utils.ts`** - Utility functions for statistics and formatting
- **`transfer.bench.ts`** - Transfer circuit benchmarks
- **`disclosure.bench.ts`** - Disclosure circuit benchmarks
- **`run-all.bench.ts`** - Orchestrator for all benchmarks

## Output

Benchmarks generate JSON files in `build/`:
- `benchmark_results_transfer.json`
- `benchmark_results_disclosure.json`
- `benchmark_results_all.json` (aggregated)

### Example Output

```
🚀 Starting Transfer Circuit Benchmarks

============================================================

📋 Circuit Information:
  Constraints:     40,912
  Private Inputs:  106
  Public Inputs:   5
  Labels:          79,944

📊 Benchmarking Proof Generation (10 iterations)...
  Warming up (3 iterations)...
  Proof Generation:
    Average:    1.43 s
    Min:        1.27 s
    Max:        1.67 s
    Std Dev:    141.64 ms
    Throughput: 0.70 ops/sec
    Memory:     17.60 KB
```

## Features

### Production-Ready
- ✅ JIT warm-up iterations
- ✅ Statistical analysis (mean, min, max, std dev)
- ✅ Memory usage tracking
- ✅ Throughput calculations
- ✅ System information capture
- ✅ Error handling and timeout protection
- ✅ JSON export for CI/CD integration

### Professional Quality
- TypeScript for type safety
- Consistent formatting and output
- Detailed circuit information
- Comprehensive error messages
- Automated result persistence

## Configuration

Edit constants in benchmark files:
```typescript
const BENCHMARK_ITERATIONS = 10;  // Number of benchmark runs
const WARMUP_ITERATIONS = 3;      // JIT warm-up runs
const TIMEOUT_MS = 120000;        // 2 minutes per circuit
```

## CI/CD Integration

Benchmark results are saved in machine-readable JSON format for integration with CI/CD pipelines:

```bash
# Run benchmarks in CI
npm run bench

# Parse results
cat build/benchmark_results_all.json | jq '.circuits.transfer.proofGen.avgTime'
```

## Performance Notes

- **Witness Generation**: Very fast (~16 μs), primarily I/O bound
- **Proof Generation**: Most expensive operation (~1.4s for 40K constraints)
- **Verification**: Fast (~7ms), suitable for on-chain verification

## Troubleshooting

**Error: Missing input.json**
```bash
# Generate required inputs first
npm run gen-input:transfer
npm run gen-input:disclosure
```

**Error: WASM/ZKey files not found**
```bash
# Compile and setup circuits
npm run full-build:transfer
npm run full-build:disclosure
```

## Development

To add a new circuit benchmark:

1. Create `your-circuit.bench.ts` following the existing pattern
2. Add to `run-all.bench.ts`
3. Add npm script to `package.json`:
   ```json
   "bench:your-circuit": "ts-node benches/your-circuit.bench.ts"
   ```

## License

Apache-2.0
