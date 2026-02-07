# Benchmarks: pallet-zk-verifier

Benchmark directory for measuring cryptographic and on-chain performance.

## 📁 Structure

```
benches/
├── config.rs           # Shared configuration (Criterion + FRAME)
├── groth16_verify.rs   # Criterion benchmarks (off-chain)
├── run.sh              # Execution script
└── README.md           # This documentation
```

## 🚀 Quick Start

```bash
# Fast benchmarks (development)
./benches/run.sh fast

# Standard benchmarks (regular)
./benches/run.sh standard

# Production benchmarks (accuracy)
./benches/run.sh production

# FRAME benchmarks (generate weights.rs)
./benches/run.sh frame
```

## 📊 Benchmark Types

### 1. Criterion Benchmarks (Off-chain)

**File:** `groth16_verify.rs`
**Purpose:** Measure pure cryptographic performance without FRAME overhead

**Available benchmarks:**
- `single_verification` - Time for single proof verification
- `batch_verification` - Throughput with 1, 5, 10, 20, 50 proofs
- `vk_operations` - Verification key parsing (transfer, unshield)
- `proof_operations` - Proof parsing
- `public_inputs_scaling` - Impact of input count (1, 2, 4, 8, 16)
- `e2e_workflow` - Complete pipeline (parse + verify)

**Configurations:**
- `fast`: 10 samples, 2s measurement (rapid development)
- `standard`: 100 samples, 10s measurement (regular)
- `production`: 200 samples, 30s measurement (maximum accuracy)

**Execute:**
```bash
# With default configuration
cargo bench --package pallet-zk-verifier

# With custom configuration
CRITERION_CONFIG=production cargo bench --package pallet-zk-verifier

# Specific benchmark
cargo bench --package pallet-zk-verifier -- single_verification

# View HTML report
open target/criterion/report/index.html
```

### 2. FRAME Benchmarks (On-chain)

**File:** `../src/benchmarking.rs`
**Purpose:** Calculate weights for on-chain fees

**Available benchmarks:**
- `register_verification_key` - Store VK in storage
- `remove_verification_key` - Remove VK from storage
- `verify_proof` - Verify proof (⚠️ uses mock data)

**Execute:**
```bash
# Build with runtime-benchmarks
cargo build --release --features runtime-benchmarks

# Generate weights.rs
./benches/run.sh frame

# Or manual:
./target/release/orbinum-node benchmark pallet \
    --chain dev \
    --pallet pallet_zk_verifier \
    --extrinsic '*' \
    --steps 50 \
    --repeat 20 \
    --output frame/zk-verifier/src/weights.rs
```

## 🔧 Configuration

### Module `config.rs`

Shared configuration for both benchmark types:

```rust
// Criterion presets
CriterionConfig::fast()        // 10 samples, 2s
CriterionConfig::standard()    // 100 samples, 10s
CriterionConfig::production()  // 200 samples, 30s

// Test sizes
BenchmarkSizes::BATCH_SIZES             // [1, 5, 10, 20, 50]
BenchmarkSizes::PUBLIC_INPUT_COUNTS     // [1, 2, 4, 8, 16]

// Test data
test_data::mock_vk_bytes(768)
test_data::mock_proof_bytes()
test_data::mock_public_inputs(count)
```

### Environment Variables

```bash
# Criterion configuration
export CRITERION_CONFIG=production

# Detailed output
export RUST_LOG=info

# Colorize output
export CARGO_TERM_COLOR=always
```

## 📈 Expected Metrics

### Criterion (Off-chain)

```
single_verification/groth16_verify           ~8-10ms
batch_verification/5                         ~40-50ms (8-10ms/proof)
vk_operations/parse_transfer_vk              ~100-200μs
proof_operations/parse_proof                 ~50-100μs
public_inputs_scaling/16                     ~10-20μs
e2e_workflow/full_verification_pipeline      ~10-12ms
```

### FRAME (On-chain)

```
register_verification_key    ~7ms + 3 DB writes
remove_verification_key      ~10ms + 4 DB writes
verify_proof                 ~13ms + 3 DB writes (⚠️ without real crypto)
```

⚠️ **Note:** Current `verify_proof` weights do NOT include real cryptographic verification time (~8-10ms) because they use mock data.

## 🔄 Typical Workflow

### Development (fast iteration)

```bash
# 1. Make code changes
vim src/infrastructure/services/groth16_verifier.rs

# 2. Quick benchmark
./benches/run.sh fast

# 3. View results
./benches/run.sh report
```

### Pre-Release (validation)

```bash
# 1. Save baseline
./benches/run.sh save

# 2. Make changes
git checkout feature-optimization

# 3. Compare
./benches/run.sh compare

# 4. If improved, generate weights
./benches/run.sh frame
```

### Production (deployment)

```bash
# 1. Run on reference hardware (not laptop)
ssh production-benchmark-server

# 2. Production benchmarks
CRITERION_CONFIG=production ./benches/run.sh production

# 3. Generate final weights
./benches/run.sh frame

# 4. Commit updated weights.rs
git add src/weights.rs
git commit -m "chore: update benchmark weights for v0.x.x"
```

## 📊 Results Interpretation

### Criterion HTML Report

```
target/criterion/report/index.html
├── single_verification/
│   ├── report/index.html          # Graphs and statistics
│   ├── base/estimates.json        # Raw data
│   └── ...
└── ...
```

**Key metrics:**
- **Mean**: Average execution time
- **Std Dev**: Standard deviation (lower = more consistent)
- **Median**: Middle value (more robust than mean)
- **MAD**: Median Absolute Deviation

**What to look for:**
- Mean < 10ms for single verification ✅
- Std Dev < 5% of mean ✅
- Outliers < 2% of samples ✅

### FRAME weights.rs

```rust
fn verify_proof() -> Weight {
    Weight::from_parts(13_000_000, 11684)
    //                  ^^^^^^^^^^  ^^^^^^
    //                  ref_time    proof_size
    //                  (picoseconds) (bytes)
}
```

**Components:**
- `ref_time`: Execution time (13ms = 13,000,000 picoseconds)
- `proof_size`: Data read from DB (11,684 bytes)

## ⚠️ Current Limitations

1. **FRAME `verify_proof` uses mock data**
   - Only measures FRAME overhead (~13ms)
   - Does NOT measure real Groth16 verification (~8-10ms)
   - Expected total weight: ~21-23ms

2. **Criterion uses real VKs but mock proofs**
   - VKs: Hardcoded from `fp-zk-verifier` (transfer, unshield)
   - Proofs: Mock data (don't verify cryptographically)
   - TODO: Use real proofs when circuits are ready

## 🛠️ Troubleshooting

### Benchmarks too slow

```bash
# Verify you're in release mode
cargo bench --package pallet-zk-verifier -- --profile-time 5

# Reduce sample size temporarily
CRITERION_CONFIG=fast ./benches/run.sh fast
```

### Inconsistent results

```bash
# Ensure no heavy processes are running
top

# Run with nice (lower priority to other processes)
nice -n -20 cargo bench --package pallet-zk-verifier
```

### FRAME benchmarks fail

```bash
# Verify feature is enabled
cargo build --release --features runtime-benchmarks

# Verify node exists
ls -lh target/release/orbinum-node
```

## 📚 References

- [Criterion.rs Book](https://bheisler.github.io/criterion.rs/book/)
- [FRAME Benchmarking](https://docs.substrate.io/test/benchmark/)
- [../README.md](../README.md) - Pallet documentation
