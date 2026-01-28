# Orbinum ZK Circuits

Zero-Knowledge circuits for Orbinum's privacy-preserving transactions.

## Overview

Orbinum uses **Groth16** proofs over the **BN254** curve for efficient on-chain verification.
Circuits are written in **Circom 2.0** and proven using **snarkjs**.

### Complete Privacy-Preserving Architecture

To enable privacy in Orbinum, the following components are generated and integrated:

1. **Circuit Definitions** (.circom files) - Define ZK logic
2. **R1CS & Artifacts** - Compiled constraint systems and witness generators
3. **Trusted Setup Ceremony** - Generate proving and verification keys
4. **Verification Keys** - Integrated into on-chain verifier (`frame/zk-verifier/`)
5. **Proofs** - Generated at runtime by clients, verified on-chain

The circuits are the **starting point**, not the only requirement. Each step is essential:

```
.circom Files → [Compilation] → R1CS + WASM → [Trusted Setup + Powers of Tau]
    → Proving Key + Verification Key → [On-chain Integration] → Privacy enabled
```

## Circuit Specifications

| Circuit | Constraints | Private Inputs | Public Inputs | Purpose |
|---------|-------------|----------------|---------------|---------|
| transfer | **40,912** | 106 | 5 | 2-in-2-out private transfer with EdDSA |
| disclosure | **1,584** | 8 | 4 | Selective disclosure of memo fields |

### Security Features

| Feature | Description |
|---------|-------------|
| **EdDSA Signature** | Each input note requires a valid EdDSA-Poseidon signature proving ownership |
| **Merkle Membership** | Proves input notes exist in the commitment tree (20 levels) |
| **Nullifier Correctness** | Prevents double-spending via deterministic nullifier computation |
| **Balance Conservation** | Ensures sum(inputs) == sum(outputs) |
| **Asset Consistency** | All notes must use the same asset_id |

### Public Inputs (5 total)
```
1. merkle_root      - Current commitment tree root (32 bytes)
2. nullifiers[0]    - Nullifier for first input note
3. nullifiers[1]    - Nullifier for second input note
4. commitments[0]   - Output commitment for first new note
5. commitments[1]   - Output commitment for second new note
```

### Private Inputs (106 total)
```
Input Notes (per note × 2):
  - input_values[i]           - Note value (amount)
  - input_asset_ids[i]        - Asset identifier (0 for native token)
  - input_blindings[i]        - Random blinding factor
  - spending_keys[i]          - Spending key for nullifier derivation
  - input_owner_Ax[i]         - EdDSA public key x-coordinate
  - input_owner_Ay[i]         - EdDSA public key y-coordinate
  - input_sig_R8x[i]          - Signature R point x-coordinate
  - input_sig_R8y[i]          - Signature R point y-coordinate
  - input_sig_S[i]            - Signature scalar

Merkle Proofs (per note × 2, depth 20):
  - input_path_elements[i][j] - Sibling hashes (20 per note)
  - input_path_indices[i][j]  - Path direction bits (20 per note)

Output Notes (per note × 2):
  - output_values[i]          - Note value
  - output_asset_ids[i]       - Asset identifier
  - output_owner_pubkeys[i]   - Recipient public key
  - output_blindings[i]       - Random blinding factor
```

---

## Directory Structure

```
circuits/
├── README.md                    # This file
├── package.json                 # Node.js dependencies
├── package-lock.json
│
├── circuits/                    # Circom source files
│   ├── transfer.circom          # Main transfer circuit (40,912 constraints)
│   ├── disclosure.circom        # Selective disclosure circuit (1,584 constraints)
│   ├── note.circom              # NoteCommitment, Nullifier templates
│   ├── merkle_tree.circom       # MerkleTreeVerifier template
│   ├── poseidon_wrapper.circom  # Poseidon2, Poseidon4 wrappers
│   └── example.circom           # Simple example circuit
│
├── build/                       # Compiled outputs
│   ├── transfer.r1cs            # R1CS constraint system (6.2MB)
│   ├── transfer.sym             # Debug symbols (5.8MB)
│   ├── transfer_js/             # WASM witness generator
│   │   ├── transfer.wasm
│   │   ├── witness_calculator.js
│   │   └── generate_witness.js
│   ├── disclosure.r1cs          # R1CS constraint system (208KB)
│   ├── disclosure.sym           # Debug symbols (129KB)
│   ├── disclosure_js/           # WASM witness generator
│   │   ├── disclosure.wasm
│   │   ├── witness_calculator.js
│   │   └── generate_witness.js
│   ├── verification_key_transfer.json    # Verification key for transfer
│   ├── verification_key_disclosure.json  # Verification key for disclosure
│   ├── input.json               # Sample transfer inputs
│   ├── proof.json               # Sample transfer proof
│   ├── public.json              # Sample transfer public signals
│   ├── disclosure_input_*.json  # 4 disclosure scenario inputs
│   ├── proof_disclosure_*.json  # 4 disclosure proofs
│   ├── public_disclosure_*.json # 4 disclosure public signals
│   └── benchmark_results_*.json # Benchmark results
│
├── keys/                        # Generated proving keys
│   ├── transfer_pk.zkey         # Transfer proving key (19MB)
│   ├── disclosure_pk.zkey       # Disclosure proving key (689KB)
│   └── witness_calculator.wasm  # WASM witness calculator (2.1MB)
│
├── ptau/                        # Powers of Tau ceremony files
│   ├── pot15_final.ptau         # 2^15 = 32,768 constraints (36MB)
│   └── pot16_final.ptau         # 2^16 = 65,536 constraints (72MB) ← REQUIRED
│
├── scripts/                     # Build and utility scripts
│   ├── e2e-transfer.ts          # End-to-end workflow for transfer circuit
│   ├── e2e-disclosure.ts        # End-to-end workflow for disclosure circuit
│   ├── build/                   # Build automation scripts
│   │   ├── compile.sh           # Compile circuit to R1CS + WASM
│   │   ├── setup.sh             # Run trusted setup ceremony
│   │   ├── convert-to-ark.sh    # Convert .zkey to .ark format
│   │   └── copy-artifacts.sh    # Copy artifacts to standard locations
│   └── generators/              # Input and proof generators
│       ├── generate_input.ts            # Generate transfer circuit inputs
│       ├── generate_proof.ts            # Generate transfer proofs
│       ├── generate_disclosure_input.ts # Generate disclosure inputs
│       └── generate_disclosure_proof.ts # Generate disclosure proofs
│
├── benches/                     # Performance benchmarks
│   ├── run-all.bench.ts         # Run all benchmarks with summary
│   ├── transfer.bench.ts        # Transfer circuit benchmarks
│   ├── disclosure.bench.ts      # Disclosure circuit benchmarks
│   ├── utils.ts                 # Benchmark utilities (stats, formatting)
│   └── types.ts                 # TypeScript types for benchmarks
│
├── test/                        # Circuit tests
│   └── transfer.test.js         # 13 tests (Poseidon, Merkle, EdDSA)
│
└── node_modules/                # Dependencies (circomlib, snarkjs, etc.)
```

---

## Quick Start

### Prerequisites

#### 1. Install Node.js (v18+)
```bash
# macOS
brew install node

# Linux (Ubuntu/Debian)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Verify
node --version  # v18.x.x or higher
npm --version   # 9.x.x or higher
```

#### 2. Install Circom Compiler
```bash
# Clone and build
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom

# Verify
circom --version  # circom compiler 2.1.x
```

#### 3. Install Circuit Dependencies
```bash
cd circuits
npm install
```

This installs:
- `circomlib` - Standard library (Poseidon, EdDSA, comparators)
- `circomlibjs` - JavaScript implementations for testing
- `snarkjs` - Proving and verification tools
- `mocha` - Test framework

---

## 🚀 Quick Setup - Generate All Keys & Builds

### Generate Everything for Transfer Circuit
```bash
cd circuits
npm run e2e:transfer
```

### Generate Everything for Disclosure Circuit
```bash
cd circuits
npm run e2e:disclosure
```

### Generate Both Circuits + Run Benchmarks
```bash
cd circuits
npm run full-build:transfer && npm run full-build:disclosure && npm run bench
```

This will generate in `circuits/build/`:
- **Compiled circuits**: `.r1cs`, `.wasm`, `.sym` files
- **Verification keys**: `verification_key_*.json`
- **Sample proofs**: `proof*.json`, `public*.json`
- **Benchmark results**: `benchmark_results_*.json`

And in `circuits/keys/`:
- **Proving keys**: `transfer_pk.zkey`, `disclosure_pk.zkey`
- **WASM calculators**: `witness_calculator.wasm`

---

## 📜 NPM Scripts Reference

### Compilation Scripts
- **`npm run compile`** - Compile transfer circuit (default)
- **`npm run compile:transfer`** - Compile transfer circuit to R1CS + WASM
- **`npm run compile:disclosure`** - Compile disclosure circuit to R1CS + WASM
- **`npm run compile:unshield`** - Compile unshield circuit to R1CS + WASM

### Setup Scripts (Generate Keys)
- **`npm run setup`** - Run trusted setup for transfer (default)
- **`npm run setup:transfer`** - Generate proving/verification keys for transfer
- **`npm run setup:disclosure`** - Generate proving/verification keys for disclosure
- **`npm run setup:unshield`** - Generate proving/verification keys for unshield

### Full Build Scripts (Compile + Setup + Convert)
- **`npm run full-build:transfer`** - Complete build pipeline for transfer
- **`npm run full-build:disclosure`** - Complete build pipeline for disclosure
- **`npm run full-build:unshield`** - Complete build pipeline for unshield

### Input Generation Scripts
- **`npm run gen-input:transfer`** - Generate sample inputs for transfer circuit
- **`npm run gen-input:disclosure`** - Generate 4 disclosure scenarios (reveal nothing/value/asset/all)

### Proof Generation Scripts
- **`npm run prove`** - Generate proof for transfer (default)
- **`npm run prove:transfer`** - Generate + verify proof for transfer circuit
- **`npm run prove:disclosure`** - Generate + verify proof for disclosure (use `DISCLOSURE_SCENARIO=reveal_all` to specify)

### End-to-End Workflow Scripts
- **`npm run e2e:transfer`** - Complete workflow: compile → setup → gen-input → prove for transfer
- **`npm run e2e:disclosure`** - Complete workflow + all 4 disclosure scenarios

### Benchmark Scripts
- **`npm run bench`** - Run benchmarks for all circuits (transfer + disclosure)
- **`npm run bench:transfer`** - Benchmark only transfer circuit
- **`npm run bench:disclosure`** - Benchmark only disclosure circuit

### Testing Scripts
- **`npm test`** - Run all Mocha tests
- **`npm run test:js`** - Run JavaScript-only tests

### Utility Scripts
- **`npm run clean`** - Remove generated build artifacts (keeps keys)
- **`npm run build`** - TypeScript compilation

---

## 🔧 Scripts & Generators Explained

### Build Scripts (`scripts/build/`)

#### `compile.sh <circuit_name>`
Compiles a Circom circuit to R1CS, WASM, and symbol files.
```bash
# Input: circuits/transfer.circom
# Output: build/transfer.r1cs, build/transfer_js/transfer.wasm, build/transfer.sym
bash scripts/build/compile.sh transfer
```

#### `setup.sh <circuit_name>`
Runs Groth16 trusted setup ceremony to generate proving and verification keys.
```bash
# Input: build/transfer.r1cs, ptau/pot16_final.ptau
# Output: keys/transfer_pk.zkey, build/verification_key_transfer.json
bash scripts/build/setup.sh transfer
```

#### `convert-to-ark.sh <circuit_name>`
Converts .zkey to .ark format (for Substrate/Rust integration).
```bash
# Input: keys/transfer_pk.zkey
# Output: keys/transfer_pk.ark (requires ark-circom)
bash scripts/build/convert-to-ark.sh transfer
```

#### `copy-artifacts.sh <circuit_name>`
Copies compiled artifacts to expected locations for easy access.
```bash
# Copies WASM and keys to standard locations
bash scripts/build/copy-artifacts.sh disclosure
```

### Generator Scripts (`scripts/generators/`)

#### `generate_input.ts`
Generates sample inputs for **transfer circuit** with EdDSA signatures.
- Creates 2 input notes (100, 50 units)
- Creates 2 output notes (80, 70 units)
- Computes EdDSA signatures for ownership proof
- Builds Merkle tree and generates membership proofs
- Saves to: `build/input.json`

```bash
ts-node scripts/generators/generate_input.ts
```

#### `generate_proof.ts`
Generates ZK proof for **transfer circuit** using pre-generated input.
- Loads `build/input.json`
- Generates witness using WASM
- Creates Groth16 proof (~1.3 seconds)
- Verifies proof locally
- Saves to: `build/proof.json`, `build/public.json`

```bash
ts-node scripts/generators/generate_proof.ts
```

#### `generate_disclosure_input.ts`
Generates 4 disclosure scenarios with different privacy levels.
- **reveal_nothing**: Full privacy (commitment only)
- **reveal_value_only**: Show amount, hide asset + owner
- **reveal_value_and_asset**: Show amount + asset type, hide owner
- **reveal_all**: Full disclosure (amount + asset + owner)
- Saves to: `build/disclosure_input_*.json` (4 files)

```bash
ts-node scripts/generators/generate_disclosure_input.ts
```

#### `generate_disclosure_proof.ts`
Generates ZK proof for **disclosure circuit** with selectable scenario.
- Supports 4 scenarios via `DISCLOSURE_SCENARIO` env var
- Generates proof (~105ms)
- Verifies proof locally
- Saves to: `build/proof_disclosure_*.json`, `build/public_disclosure_*.json`

```bash
DISCLOSURE_SCENARIO=reveal_value_only ts-node scripts/generators/generate_disclosure_proof.ts
```

### End-to-End Workflow Scripts (`scripts/`)

#### `e2e-transfer.ts`
Master orchestrator for **transfer circuit** workflow.
- Step 1: Compile circuit (`npm run compile:transfer`)
- Step 2: Generate keys (`npm run setup:transfer`)
- Step 3: Generate sample inputs (`npm run gen-input:transfer`)
- Step 4: Generate proof (`npm run prove`)
- Saves all artifacts to `build/` directory

```bash
ts-node scripts/e2e-transfer.ts
# or
npm run e2e:transfer
```

#### `e2e-disclosure.ts`
Master orchestrator for **disclosure circuit** workflow.
- Step 1-3: Compile + Setup + Convert
- Step 4: Generate 4 disclosure scenarios
- Step 5: Generate proofs for all scenarios
- Creates 4 proofs (reveal_nothing, reveal_value_only, reveal_value_and_asset, reveal_all)

```bash
ts-node scripts/e2e-disclosure.ts
# or
npm run e2e:disclosure
```

### Benchmark Scripts (`benches/`)

#### `transfer.bench.ts`
Professional benchmark for transfer circuit.
- Warm-up phase (3 iterations for JIT)
- Witness generation (10 iterations)
- Proof generation (10 iterations)
- Verification (100 iterations)
- Calculates: mean, min, max, stddev, throughput
- Saves to: `build/benchmark_results_transfer.json`

#### `disclosure.bench.ts`
Professional benchmark for disclosure circuit.
- Same structure as transfer benchmark
- Tests with reveal_value_only scenario by default
- Saves to: `build/benchmark_results_disclosure.json`

#### `run-all.bench.ts`
Orchestrates all benchmarks with aggregated results.
- Runs transfer + disclosure benchmarks
- Timeout protection per circuit
- Aggregated summary with comparison
- Saves to: `build/benchmark_results_all.json`

```bash
npm run bench
```

#### `utils.ts` & `types.ts`
Shared utilities and TypeScript types for benchmarks.
- `calculateStats()`: Statistical analysis (mean, stddev, throughput)
- `formatTime()`, `formatMemory()`: Pretty printing
- `warmUp()`: JIT warm-up helper
- Type definitions: `BenchmarkResult`, `CircuitInfo`, `SystemInfo`

---

## Complete Build Process

### Overview: What Gets Generated?

The build process produces multiple critical artifacts:

| Artifact | Generated By | Purpose |
|----------|--------------|---------|
| transfer.r1cs | Circom compiler | Constraint system (used in setup) |
| transfer.wasm + witness_calculator.js | Circom compiler | Generate witness from inputs |
| transfer_pk.zkey | Trusted setup ceremony | **Proving key** (client-side, 19MB) |
| disclosure_pk.zkey | Trusted setup ceremony | **Proving key** (client-side, 689KB) |
| verification_key_*.json | Trusted setup ceremony | **Verification keys** (on-chain, ~3KB each) |

**Critical:** The `verification_key.json` must be integrated into [frame/zk-verifier/src/circuits/](../frame/zk-verifier/src/circuits/) for on-chain verification to work.

---

### Step 1: Compile Circuit

```bash
cd circuits

# Using npm script
npm run compile:transfer

# Or manually
circom circuits/transfer.circom \
    --r1cs \
    --wasm \
    --sym \
    -o build/
```

**Expected output:**
```
template instances: 282
non-linear constraints: 40912
linear constraints: 0
public inputs: 5
private inputs: 106
public outputs: 0
wires: 41003
labels: 82232
Written successfully: build/transfer.r1cs
Written successfully: build/transfer.sym
Written successfully: build/transfer_js/transfer.wasm
Everything went okay
```

### Step 2: Download Powers of Tau

The transfer circuit has 40,912 constraints, so we need `pot16` (supports up to 65,536):

```bash
mkdir -p ptau

# Download pot16 (72MB) - REQUIRED for this circuit
curl -L "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau" \
    -o ptau/pot16_final.ptau

# Verify size
ls -lh ptau/pot16_final.ptau  # Should be ~72MB
```

### Step 3: Trusted Setup Ceremony (Groth16)

This is the **critical ceremony** that generates both:
- **Proving key** (`transfer_final.zkey`) - Used by clients to generate proofs
- **Verification key** (`verification_key.json`) - Used by the blockchain to verify proofs

The "ceremony" involves:
1. **Phase 1 (Setup)**: Combine R1CS with Powers of Tau to create initial zkey
2. **Phase 2 (Contribution)**: Add randomness/entropy to zkey (increases security with each contributor)
3. **Phase 2 (Beacon)**: Finalize zkey using deterministic beacon value

**⚠️ Security Note:** This is a simplified development ceremony. For production, you need a **multi-party computation (MPC) ceremony** with 50+ independent participants. Each participant adds randomness that cannot be reversed unless ALL participants collude. This randomness ("toxic waste") must be destroyed.

```bash
cd circuits

# Phase 1: Initial setup from r1cs and ptau
npx snarkjs groth16 setup \
    build/transfer.r1cs \
    ptau/pot16_final.ptau \
    build/transfer_0000.zkey

# Phase 2: Add contribution (adds randomness/entropy)
# This is where multi-party ceremony happens in production
npx snarkjs zkey contribute \
    build/transfer_0000.zkey \
    build/transfer_0001.zkey \
    --name="First contribution" \
    -e="random entropy string here"

# Phase 2: Finalize with beacon (deterministic finalization)
# Beacon value should be publicly verifiable (e.g., hash of future block)
npx snarkjs zkey beacon \
    build/transfer_0001.zkey \
    build/transfer_final.zkey \
    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    10 \
    -n="Final Beacon phase2"

# Export verification key (for on-chain verifier)
# THIS FILE MUST BE INTEGRATED INTO zk-verifier
npx snarkjs zkey export verificationkey \
    build/transfer_final.zkey \
    build/verification_key.json
```

### Step 4: Integrate Verification Key into On-Chain Verifier

After the ceremony completes, you **MUST integrate** the generated `verification_key.json` into the blockchain verifier:

```bash
# 1. Copy the verification key to zk-verifier
cp circuits/build/verification_key.json \
   frame/zk-verifier/src/circuits/transfer_vk.json

# 2. Update frame/zk-verifier/src/lib.rs to load the verification key
#    The verifier uses arkworks to verify Groth16 proofs against this key

# 3. Regenerate Substrate types if needed
# (depends on how the verification key is encoded)
```

The verification key is used by the **Groth16 verifier precompile** in the runtime to verify:
- Each proof's validity
- Each proof's public inputs (merkle_root, nullifiers, commitments)

**Without this integration, on-chain verification will fail.**

### Step 5: Verify Setup (Optional but Recommended)

```bash
npx snarkjs zkey verify \
    build/transfer.r1cs \
    ptau/pot16_final.ptau \
    build/transfer_final.zkey
```

Should output: `[INFO] snarkJS: ZKey Ok!`

---

## Verification Key Integration Guide

### What is verification_key.json?

A JSON file containing elliptic curve points that represent the public parameters of the proving ceremony. Example structure:

```json
{
  "protocol": "groth16",
  "curve": "bn128",
  "nPublic": 5,
  "vk_alpha_1": ["x", "y"],
  "vk_beta_2": [["x1", "x2"], ["y1", "y2"]],
  "vk_gamma_2": [...],
  "vk_delta_2": [...],
  "vk_alphabeta_12": [...],
  "IC": [
    ["root_x", "root_y"],
    ["nullifier0_x", "nullifier0_y"],
    ["nullifier1_x", "nullifier1_y"],
    ["commitment0_x", "commitment0_y"],
    ["commitment1_x", "commitment1_y"]
  ]
}
```

### Where is it Used?

See [frame/zk-verifier/src/lib.rs](../frame/zk-verifier/src/lib.rs) - The Groth16 verifier loads this key and uses it to verify proofs via the arkworks library.

### How to Update It

1. Generate new verification key (see Step 4 above)
2. Convert JSON to Rust constant (or load from storage)
3. Update the circuit circuit mapping in zk-verifier
4. Test with `cargo test -p zk-verifier`

---

### Step 2: Download Powers of Tau (MOVED - See above in ceremony)

## Generating Proofs

### Using the Proof Script

```bash
npm run prove
# or
node scripts/generate_proof.js
```

This script:
1. Creates sample input/output notes
2. Builds a Merkle tree
3. Computes nullifiers
4. Generates witness
5. Creates Groth16 proof
6. Verifies locally (off-chain)
7. Exports to Substrate format

### Manual Proof Generation

```bash
cd circuits

# 1. Calculate witness from inputs
node build/transfer_js/generate_witness.js \
    build/transfer_js/transfer.wasm \
    build/input.json \
    build/witness.wtns

# 2. Generate Groth16 proof
npx snarkjs groth16 prove \
    build/transfer_final.zkey \
    build/witness.wtns \
    build/proof.json \
    build/public.json

# 3. Verify proof off-chain
npx snarkjs groth16 verify \
    build/verification_key.json \
    build/public.json \
    build/proof.json
```

Should output: `[INFO] snarkJS: OK!`

---

## Integration with Rust/Substrate

### Client-Side: Proof Generation

The `scripts/proof_wrapper.js` script provides a JSON interface for the Rust wallet-cli to generate proofs:

```bash
# Called from Rust via subprocess
echo '{"action":"prove","input":{...}}' | node scripts/proof_wrapper.js
```

The client uses:
- `transfer_final.zkey` (proving key) to generate proofs
- `transfer_js/transfer.wasm` (witness generator) to compute witness from inputs

### On-Chain: Proof Verification

The blockchain verifies proofs using the **verification key** and the **Groth16 verifier** in `frame/zk-verifier/`:

```
Client generates proof with transfer_final.zkey
              ↓
Client submits proof + public_inputs to transaction
              ↓
On-chain Groth16 verifier receives proof
              ↓
Verifier loads verification_key.json from frame/zk-verifier/
              ↓
Verifier checks: proof.verify(vk, public_inputs)
              ↓
If valid: transfers are processed (commitment tree updated, nullifiers added)
If invalid: transaction reverts
```

### Verification Key in Rust

The `verification_key.json` is integrated into `frame/zk-verifier/src/circuits/` and loaded by the Groth16 verifier (uses arkworks library).

**Required steps after ceremony:**
1. Export verification key from ceremony: `npx snarkjs zkey export verificationkey ...`
2. Copy to `frame/zk-verifier/src/circuits/transfer_vk.json`
3. Update `frame/zk-verifier/src/lib.rs` to load the new key
4. Run tests: `cargo test -p zk-verifier`
5. Build runtime: `cargo build --release --package orbinum-runtime`

---

## Integration with Rust/Substrate (Client-Side)

### Proof Wrapper for CLI

---

## Running Tests

```bash
cd circuits
npm test
```

**Expected output:**
```
  Transfer Circuit Logic
    Note Commitment
      ✔ should compute note commitment correctly
      ✔ should produce different commitments for different values
      ✔ should be deterministic (same inputs = same output)
    Nullifier
      ✔ should compute nullifier correctly
      ✔ should be unlinkable (different spending keys)
    Merkle Tree
      ✔ should compute merkle root for 2-leaf tree
      ✔ should verify merkle path (depth 2)
    Balance Conservation
      ✔ should enforce balance equality
      ✔ should reject imbalanced transfer
    EdDSA Ownership Verification
      ✔ should generate valid EdDSA signature
      ✔ should reject invalid signature
      ✔ should link EdDSA public key to note commitment
    Complete Transfer Example
      ✔ should simulate valid transfer

  13 passing
```

---

## Circuit Architecture

### Transfer Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TRANSFER CIRCUIT                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  INPUT NOTES (2)                          OUTPUT NOTES (2)              │
│  ┌─────────────────┐                      ┌─────────────────┐          │
│  │ value: 100      │                      │ value: 80       │          │
│  │ asset_id: 0     │                      │ asset_id: 0     │          │
│  │ owner: Ax       │──┐                   │ owner: Bob_pk   │          │
│  │ blinding: r1    │  │                   │ blinding: r3    │          │
│  └─────────────────┘  │                   └─────────────────┘          │
│         │             │                            │                    │
│         ▼             │                            ▼                    │
│  ┌─────────────────┐  │                   ┌─────────────────┐          │
│  │ NoteCommitment  │  │                   │ NoteCommitment  │          │
│  │ Poseidon4(...)  │  │                   │ Poseidon4(...)  │          │
│  └────────┬────────┘  │                   └────────┬────────┘          │
│           │           │                            │                    │
│           ▼           │                            ▼                    │
│  ┌─────────────────┐  │                   ┌─────────────────┐          │
│  │ MerkleVerifier  │  │                   │ PUBLIC OUTPUT   │          │
│  │ (20 levels)     │  │                   │ commitment[0]   │──────────┼──► PUBLIC
│  └────────┬────────┘  │                   └─────────────────┘          │
│           │           │                                                 │
│           ▼           │                                                 │
│  ┌─────────────────┐  │    ┌─────────────────┐                         │
│  │ EdDSA Verifier  │◄─┘    │ Balance Check   │                         │
│  │ sig over commit │       │ 100+50 = 80+70  │                         │
│  └────────┬────────┘       └────────┬────────┘                         │
│           │                         │                                   │
│           ▼                         ▼                                   │
│  ┌─────────────────┐       ┌─────────────────┐                         │
│  │ Nullifier       │       │ CONSTRAINT      │                         │
│  │ Poseidon2(...)  │       │ input_sum ===   │                         │
│  └────────┬────────┘       │ output_sum      │                         │
│           │                └─────────────────┘                         │
│           ▼                                                             │
│  ┌─────────────────┐                                                   │
│  │ PUBLIC OUTPUT   │                                                   │
│  │ nullifier[0]    │───────────────────────────────────────────────────┼──► PUBLIC
│  └─────────────────┘                                                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Constraint Breakdown

| Component | Constraints (approx) |
|-----------|---------------------|
| Poseidon hash (×8) | ~3,200 |
| Merkle verification (×2, 20 levels) | ~15,000 |
| EdDSA verification (×2) | ~20,000 |
| Balance + asset checks | ~100 |
| Range checks & comparisons | ~2,600 |
| **Total** | **~40,912** |

---

## NPM Scripts Reference

```json
{
  "scripts": {
    "compile:transfer": "circom circuits/transfer.circom --r1cs --wasm --sym -o build/",
    "setup": "./scripts/setup.sh transfer",
    "prove": "node scripts/generate_proof.js",
    "test": "mocha test/**/*.test.js --timeout 100000"
  }
}
```

---

## Performance

| Operation | Transfer Circuit | Disclosure Circuit | Hardware |
|-----------|------------------|-------------------|----------|
| Compilation | ~15s | ~3s | Any |
| Trusted Setup | ~60s | ~20s | Any |
| Witness Generation | ~16μs | ~25μs | M4 Mac |
| Proof Generation | ~1.3s | ~105ms | M4 Mac |
| Proof Verification | ~5.7ms | ~5.6ms | M4 Mac |

**Proof Size**: 192 bytes (Groth16)

---

## Security Considerations

### ⚠️ Trusted Setup Ceremony - Critical for Production

The **trusted setup ceremony** is the most security-critical step. Here's what you need to understand:

#### What is a Ceremony?

A ceremony is a **multi-party computation (MPC)** where multiple independent participants:
1. Each add randomness to the zkey
2. Create a contribution proof
3. Destroy their randomness ("toxic waste")

**Example with 3 participants:**
```
Initial R1CS + Powers of Tau
       ↓
Alice contributes randomness → transfer_0001.zkey (Alice cannot forge proofs alone)
       ↓ Alice destroys her randomness
Bob contributes randomness → transfer_0002.zkey (Alice + Bob needed to forge)
       ↓ Bob destroys his randomness
Charlie contributes randomness → transfer_0003.zkey (All 3 would need to collude)
       ↓ Charlie destroys his randomness
Beacon finalizes → transfer_final.zkey (Ready for deployment)
```

**Security property:** If ANY single participant honestly destroys their randomness, the system is secure. Only if ALL participants collude can proofs be forged.

#### Current Status (Development)

The current setup is a **development/testing ceremony** with minimal contributors:
```bash
npx snarkjs zkey contribute build/transfer_0000.zkey build/transfer_0001.zkey
```

This is NOT secure for production because:
- Only 1-2 contributors (might be same person/machine)
- Randomness might not be destroyed
- No public verification of contributions

#### For Production Deployment

1. **Coordinate a multi-party ceremony**
   - Target: 50-100+ independent participants
   - Participants from different organizations/countries
   - Different OS, hardware, networks

2. **Use established ceremony frameworks**
   - Hermez (Powers of Tau: https://ceremony.hermez.io/)
   - Zcash Sapling (https://github.com/zcash-hackworks/sapling-mpc)
   - Filecoin (https://github.com/arturomerra/phase2-bn254)

3. **Publish ceremony documentation**
   - List all participants
   - Publish contribution hashes
   - Timeline and schedule
   - Communication channels

4. **Verify contributions publicly**
   ```bash
   # Anyone can verify that Bob's contribution is valid
   npx snarkjs zkey verify build/transfer_0001.zkey build/transfer_0002.zkey
   ```

5. **Finalize with public beacon**
   ```bash
   # Use a future block hash or trusted source (not a secret)
   npx snarkjs zkey beacon build/transfer_0003.zkey build/transfer_final.zkey <beacon_value>
   ```

#### Why This Matters for Privacy

If an attacker has the "toxic waste" randomness from the ceremony:
- ✅ They CAN create valid proofs for false transfers
- ✅ They can forge nullifiers (double-spend)
- ✅ They can create fake commitments
- ✅ Privacy is completely broken

With a multi-party ceremony:
- ❌ Attacker needs ALL participants' randomness
- ❌ Must infiltrate 50+ independent organizations
- ❌ Must compromise diverse hardware/OS/networks
- ✅ Practically impossible

---

### Audit Checklist

- [x] EdDSA signature verification
- [x] Merkle tree membership proofs
- [x] Nullifier uniqueness
- [x] Balance conservation
- [x] Asset ID consistency
- [ ] Multi-party ceremony (production requirement)
- [ ] Formal verification (future)
- [ ] Third-party audit (future)

---

## Troubleshooting

### "circuit too big for this power of tau ceremony"

Download a larger ptau file:
```bash
# For circuits up to 65,536 constraints
curl -L "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau" \
    -o ptau/pot16_final.ptau
```

### "circom: command not found"

Add cargo bin to PATH:
```bash
export PATH=$PATH:~/.cargo/bin
# Add to ~/.zshrc or ~/.bashrc for persistence
```

### "JavaScript heap out of memory"

Increase Node.js memory:
```bash
export NODE_OPTIONS="--max-old-space-size=8192"
npm run prove
```

### Slow compilation

Use optimization flags:
```bash
circom --O1 circuits/transfer.circom ...  # Basic optimization
circom --O2 circuits/transfer.circom ...  # Full optimization (slower compile)
```

---

## Resources

- [Circom Documentation](https://docs.circom.io/)
- [snarkjs GitHub](https://github.com/iden3/snarkjs)
- [circomlib Circuits](https://github.com/iden3/circomlib)
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [EdDSA on BabyJubjub](https://eips.ethereum.org/EIPS/eip-2494)
- [Poseidon Hash](https://eprint.iacr.org/2019/458.pdf)

---

## License

Apache-2.0 / GPL-3.0 (see root LICENSE files)
