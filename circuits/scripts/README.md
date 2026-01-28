# Circuit Scripts

This directory contains scripts for building circuits and generating proofs, organized by purpose:

```
scripts/
├── build/          # Circuit compilation and setup (Bash)
├── generators/     # Input and proof generation (TypeScript)
└── utils/          # Format conversion utilities (Rust)
```

## Building Circuits from Scratch

This guide shows how to build the complete circuit pipeline from zero. We'll start with a clean slate and build the `disclosure` circuit as an example.

### Initial Setup

```bash
# Navigate to circuits directory
cd circuits

# Verify clean state (no previous builds)
rm -rf keys build pot16_final.ptau

# Install Node.js dependencies
npm install
```

### Prerequisites Check

Before building, ensure you have these tools installed:

```bash
# Check circom
circom --version
# If not found: https://docs.circom.io/getting-started/installation/

# Check snarkjs (installed with npm install)
npx snarkjs --version

# Check ark-circom (optional, for Substrate integration)
ark-circom --version
# If not found: cargo install ark-circom
```

### Step 1: Compile the Circuit

This creates the constraint system (R1CS) and witness calculator (WASM).

```bash
bash scripts/build/compile.sh disclosure
```

**What it does:**
- Reads `circuits/disclosure.circom`
- Generates `build/disclosure.r1cs` (constraint system)
- Generates `build/disclosure_js/disclosure.wasm` (witness calculator)
- Generates `build/disclosure.sym` (debug symbols)
- Shows constraint count and wire count

**Expected output:**
```
═══════════════════════════════════════════════════════
  Orbinum Circuit Compilation Script
═══════════════════════════════════════════════════════
✓ Found circom: circom compiler 2.x.x
Compiling circuit: disclosure
Generating R1CS, WASM, and symbols...
✓ Compilation successful!

Constraint count: 24,740
Wire count: 24,823
```

**Generated files:**
```
circuits/
└── build/
    ├── disclosure.r1cs           # 2.1 MB - Constraint system
    ├── disclosure.sym             # Symbol file for debugging
    └── disclosure_js/
        ├── disclosure.wasm        # 645 KB - Witness calculator
        ├── witness_calculator.js
        └── generate_witness.js
```

### Step 2: Run Trusted Setup

This generates the cryptographic keys needed for proving and verification.

```bash
bash scripts/build/setup.sh disclosure
```

**What it does:**
1. Downloads Powers of Tau file (`pot16_final.ptau`, ~50MB, one-time download)
2. Runs Phase 2 ceremony (circuit-specific setup)
3. Generates proving key with random beacon
4. Exports verification key
5. Shows key information

**Expected output:**
```
═══════════════════════════════════════════════════════
  Orbinum Trusted Setup Script
═══════════════════════════════════════════════════════
✓ Found snarkjs: snarkjs@0.7.x

Step 1: Download Powers of Tau
Downloading Powers of Tau (2^15 = 32768 constraints)...
✓ Downloaded pot16_final.ptau

Step 2: Phase 2 Setup
Starting Phase 2 (circuit-specific setup)...
✓ Generated proving key: keys/disclosure_pk.zkey

Step 3: Apply Random Beacon
Applying final random beacon...
✓ Applied beacon to: keys/disclosure_pk.zkey

Step 4: Export Verification Key
✓ Exported: build/verification_key_disclosure.json

Setup complete!
```

**Generated files:**
```
circuits/
├── pot16_final.ptau                         # 50 MB - Powers of Tau (cached)
├── keys/
│   └── disclosure_pk.zkey                   # 45 MB - Proving key
└── build/
    └── verification_key_disclosure.json     # 1 KB - Verification key
```

### Step 3: Convert to Arkworks Format (Optional)

If you're integrating with Substrate/Rust, convert the proving key to Arkworks format:

```bash
bash scripts/build/convert-to-ark.sh disclosure
```

**What it does:**
- Converts `.zkey` (snarkjs format) to `.ark` (arkworks format)
- Arkworks format is smaller and faster for Substrate verification

**Expected output:**
```
═══════════════════════════════════════════════════════
  Convert .zkey to .ark Format
═══════════════════════════════════════════════════════
✓ Found ark-circom: v0.x.x
Converting disclosure_pk.zkey to .ark format...
✓ Conversion successful!

File sizes:
  • Original .zkey: 45M
  • Arkworks .ark: 42M
```

**Generated files:**
```
circuits/
└── keys/
    ├── disclosure_pk.zkey     # 45 MB - snarkjs format
    └── disclosure_pk.ark      # 42 MB - arkworks format
```

### Step 4: Copy Artifacts

Copy generated files to locations expected by the runtime:

```bash
bash scripts/build/copy-artifacts.sh disclosure
```

**What it does:**
- Copies WASM witness calculator to standard location
- Organizes verification keys
- Prepares artifacts for runtime integration

### Step 5: Generate Metadata (Optional)

Extract circuit information for benchmarks and documentation:

```bash
bash scripts/build/generate-metadata.sh
```

**What it does:**
- Reads R1CS files
- Extracts constraint count, wire count, signal names
- Creates JSON metadata files

**Generated files:**
```
circuits/
└── build/
    ├── disclosure_metadata.json
    ├── transfer_metadata.json
    └── unshield_metadata.json
```

### Complete Build Summary

After running all steps, your directory structure will be:

```
circuits/
├── pot16_final.ptau                         # 50 MB - Powers of Tau (reusable)
├── build/
│   ├── disclosure.r1cs                      # 2.1 MB - Constraints
│   ├── disclosure.sym                       # Debug symbols
│   ├── disclosure_metadata.json             # Circuit info
│   ├── verification_key_disclosure.json     # 1 KB - Verification key
│   └── disclosure_js/
│       ├── disclosure.wasm                  # 645 KB - Witness calculator
│       ├── witness_calculator.js
│       └── generate_witness.js
└── keys/
    ├── disclosure_pk.zkey                   # 45 MB - Proving key
    ├── disclosure_pk.ark                    # 42 MB - Arkworks format
    └── witness_calculator.wasm              # Copied WASM
```

### Automated Full Build

Run all steps with one command:

```bash
npm run full-build:disclosure
```

This executes:
1. `compile.sh disclosure`
2. `setup.sh disclosure`
3. `convert-to-ark.sh disclosure`
4. `copy-artifacts.sh disclosure`

### Using Generators to Create Proofs

Now that the circuit is built, use the generators to create and verify proofs:

#### Generate Test Inputs

```bash
npx ts-node scripts/generators/generate_disclosure_input.ts
```

**What it does:**
- Creates sample private note data
- Generates Merkle tree paths
- Produces `input.json` file ready for proving

**Output:**
```json
{
  "root": "0x1234...",
  "nullifier": "0x5678...",
  "commitment": "0x9abc...",
  "recipient": "0xdef0...",
  "amount": "1000000000000000000",
  "pathElements": [...],
  "pathIndices": [...]
}
```

#### Generate and Verify Proof

```bash
npx ts-node scripts/generators/generate_proof.ts
```

**What it does:**
1. Loads input from `input.json`
2. Calculates witness using WASM
3. Generates zero-knowledge proof
4. Verifies proof with verification key
5. Shows proof generation time

**Expected output:**
```
Generating proof for disclosure circuit...
✓ Witness calculated (1.2s)
✓ Proof generated (3.4s)
✓ Proof verified successfully!

Proof generation time: 4.6s

Proof:
{
  "pi_a": [...],
  "pi_b": [...],
  "pi_c": [...],
  "protocol": "groth16"
}

Public signals:
{
  "root": "0x1234...",
  "nullifier": "0x5678..."
}
```

### Building Other Circuits

Apply the same process to other circuits:

```bash
# Transfer circuit
bash scripts/build/compile.sh transfer
bash scripts/build/setup.sh transfer
npx ts-node scripts/generators/generate_input.ts

# Unshield circuit
bash scripts/build/compile.sh unshield
bash scripts/build/setup.sh unshield
```

### Generator Scripts Reference

**generate_disclosure_input.ts**
- Creates inputs for selective disclosure circuit
- Generates Merkle proofs for note verification

**generate_input.ts**
- Creates inputs for transfer circuit
- Handles sender/receiver note commitments

**generate_proof.ts**
- Universal proof generator
- Works with any circuit (transfer, unshield, disclosure)
- Verifies proof automatically

**eddsa_signer.ts**
- EdDSA signature generation
- Used for authenticating note ownership

**proof_wrapper.ts**
- Stdin/stdout wrapper for Rust integration
- Enables proof generation from Substrate runtime

### Testing Your Build

Run the test suite to verify everything works:

```bash
npm test
```

This runs all circuit tests including:
- Unit tests for individual components
- Integration tests for full circuits
- Compatibility tests with Rust implementation

Expected: **73 tests passing** in ~7 seconds

### Troubleshooting

**Error: "circom not found"**
```bash
# Install Circom
curl -sSL https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 -o /usr/local/bin/circom
chmod +x /usr/local/bin/circom
```

**Error: "snarkjs not found"**
```bash
# Use npx (no global install needed)
npx snarkjs --version

# Or install globally
npm install -g snarkjs
```

**Error: "R1CS file not found"**
- You need to run Step 1 (compile.sh) first
- The setup script requires the compiled R1CS file

**Error: "Powers of Tau download fails"**
```bash
# Download manually
curl -L https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau -o pot16_final.ptau
```

**Error: "ark-circom not found"**
- Only needed for Substrate integration (Step 3)
- Install: `cargo install ark-circom`
- You can skip this step if not using Rust/Substrate

**Build takes too long / runs out of memory**
- The disclosure circuit has 24,740 constraints
- Ensure you have at least 4GB RAM available
- Trusted setup takes 2-3 minutes on modern hardware

**Want to rebuild from scratch?**
```bash
cd circuits
rm -rf keys build pot16_final.ptau
npm run full-build:disclosure
```

## Script Reference

### Build Scripts (`build/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| `compile.sh` | Compile Circom → R1CS + WASM | `bash scripts/build/compile.sh <circuit>` |
| `setup.sh` | Trusted setup → Keys | `bash scripts/build/setup.sh <circuit>` |
| `convert-to-ark.sh` | Convert to Arkworks | `bash scripts/build/convert-to-ark.sh <circuit>` |
| `copy-artifacts.sh` | Copy to runtime locations | `bash scripts/build/copy-artifacts.sh <circuit>` |
| `generate-metadata.sh` | Extract circuit info | `bash scripts/build/generate-metadata.sh` |

### Generator Scripts (`generators/`)

| Script | Purpose | Input | Output |
|--------|---------|-------|--------|
| `generate_disclosure_input.ts` | Create disclosure inputs | Circuit params | `input.json` |
| `generate_input.ts` | Create transfer inputs | Note data | `input.json` |
| `generate_proof.ts` | Generate & verify proof | `input.json` | Proof + verification |
| `eddsa_signer.ts` | Sign data with EdDSA | Private key | Signature |
| `proof_wrapper.ts` | Rust integration wrapper | stdin JSON | stdout proof |

### Utility Scripts (`utils/`)

| Script | Purpose | Language |
|--------|---------|----------|
| `convert_proof.rs` | Convert proof formats | Rust |
| `convert_zkey_to_ark.rs` | Convert keys to Arkworks | Rust |

## Complete Circuit Build Flow

This is the complete workflow to build a circuit from source to production-ready artifacts:

### Prerequisites

```bash
# Install system dependencies
# 1. Circom compiler (https://docs.circom.io/getting-started/installation/)
curl -sSL https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 -o /usr/local/bin/circom
chmod +x /usr/local/bin/circom

# 2. Rust toolchain (for ark-circom conversion)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install ark-circom

# 3. Node.js dependencies
cd circuits
npm install
```

### Step-by-Step Build Process

#### Step 1: Compile Circuit → R1CS + WASM

Compiles the Circom circuit into:
- `.r1cs` - Rank-1 Constraint System (circuit constraints)
- `.wasm` - WebAssembly witness calculator
- `.sym` - Symbol file for debugging

```bash
bash scripts/build/compile.sh disclosure
```

**Output:**
- `build/disclosure.r1cs`
- `build/disclosure_js/disclosure.wasm`
- `build/disclosure.sym`

#### Step 2: Trusted Setup → Proving/Verification Keys

Downloads Powers of Tau (if needed) and generates:
- Proving key (`.zkey`) - Used to generate proofs
- Verification key (`.json`) - Used to verify proofs

```bash
bash scripts/build/setup.sh disclosure
```

**Output:**
- `keys/disclosure_pk.zkey` (~45 MB)
- `build/verification_key_disclosure.json`

**What happens:**
1. Downloads `pot16_final.ptau` (Powers of Tau, ~50MB, one-time)
2. Runs Phase 2 ceremony (circuit-specific setup)
3. Generates proving key with random beacon
4. Exports verification key

#### Step 3: Convert to Arkworks Format (Optional)

Converts `.zkey` to `.ark` format for faster verification in Substrate/Rust:

```bash
bash scripts/build/convert-to-ark.sh disclosure
```

**Output:**
- `keys/disclosure_pk.ark` (Arkworks format, smaller & faster)

#### Step 4: Copy Artifacts to Expected Locations

Copies generated files to locations expected by the runtime:

```bash
bash scripts/build/copy-artifacts.sh disclosure
```

**Copies:**
- `build/disclosure_js/disclosure.wasm` → `keys/witness_calculator.wasm`
- Verification key to expected location

#### Step 5: Generate Metadata (Optional)

Extracts circuit metadata (constraint count, signal names) for benchmarks:

```bash
bash scripts/build/generate-metadata.sh
```

**Output:**
- `build/disclosure_metadata.json`
- Contains constraint count, signal info without needing R1CS at runtime

### Automated Build (All Steps)

Run all steps automatically:

```bash
cd circuits

# Full build for disclosure circuit
npm run full-build:disclosure

# Or manually with one command:
bash scripts/build/compile.sh disclosure && \
bash scripts/build/setup.sh disclosure && \
bash scripts/build/convert-to-ark.sh disclosure && \
bash scripts/build/copy-artifacts.sh disclosure
```

### Build Output Summary

After a complete build, you'll have:

```
circuits/
├── build/
│   ├── disclosure.r1cs           # Circuit constraints
│   ├── disclosure.sym             # Debug symbols
│   ├── disclosure_metadata.json   # Circuit info
│   ├── verification_key_disclosure.json  # Verification key
│   └── disclosure_js/
│       └── disclosure.wasm        # Witness calculator
├── keys/
│   ├── disclosure_pk.zkey         # Proving key (snarkjs format)
│   ├── disclosure_pk.ark          # Proving key (arkworks format)
│   └── witness_calculator.wasm    # Copied WASM
└── pot16_final.ptau              # Powers of Tau (cached)
```

### Testing the Build

Generate a proof to verify everything works:

```bash
# 1. Generate test inputs
npx ts-node scripts/generators/generate_disclosure_input.ts

# 2. Generate and verify proof
npx ts-node scripts/generators/generate_proof.ts
```

### Build Individual Circuits

```bash
# Transfer circuit
bash scripts/build/compile.sh transfer
bash scripts/build/setup.sh transfer

# Unshield circuit
bash scripts/build/compile.sh unshield
bash scripts/build/setup.sh unshield

# Disclosure circuit
bash scripts/build/compile.sh disclosure
bash scripts/build/setup.sh disclosure
```

### Troubleshooting

**"circom not found"**
- Install Circom: https://docs.circom.io/getting-started/installation/

**"snarkjs not found"**
- Install globally: `npm install -g snarkjs`
- Or use npx: `npx snarkjs`

**"ark-circom not found"**
- Install: `cargo install ark-circom`
- Only needed for Step 3 (Arkworks conversion)

**"R1CS file not found"**
- Run Step 1 first (compile.sh)

**"Powers of Tau download fails"**
- Download manually from: https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau
- Place in `circuits/pot16_final.ptau`

## Quick Start

```bash
# Install dependencies
cd circuits
npm install

# Build a circuit (automated)
npm run full-build:disclosure

# Or step-by-step
bash scripts/build/compile.sh disclosure
bash scripts/build/setup.sh disclosure

# Generate test proof
npx ts-node scripts/generators/generate_disclosure_input.ts
npx ts-node scripts/generators/generate_proof.ts
```
