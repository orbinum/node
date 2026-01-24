# fp-zk-circuits

R1CS circuits and constraint gadgets for Zero-Knowledge proof generation in Orbinum Network.

## What is this?

This crate **generates Zero-Knowledge proofs off-chain** using R1CS (Rank-1 Constraint System). It provides:

- **Gadgets**: R1CS constraint-generating versions of cryptographic primitives
- **Circuits**: Complete ZK-SNARK circuits (transfer, unshield)

**This is NOT used by the runtime**. The runtime only needs `fp-zk-verifier` to verify proofs on-chain.

## The 3-Crate Architecture

```
┌─────────────────────────────────────────────────────────┐
│ fp-zk-primitives (Native Crypto)                        │
│ • Poseidon, commitments, Merkle trees                   │
│ • Direct computation (fast)                             │
│ • USE: Wallets, runtime, tests                          │
└─────────────────────────────────────────────────────────┘
                      ▲
                      │ (validates compatibility)
                      │
┌─────────────────────────────────────────────────────────┐
│ fp-zk-circuits (Proof Generation) ◄── THIS CRATE       │
│ • R1CS constraint gadgets                               │
│ • Complete circuits (transfer, unshield)                │
│ • GENERATES proofs off-chain                            │
│ • USE: Wallets, CLI tools, proof servers               │
└─────────────────────────────────────────────────────────┘
                      │
                      │ (generates)
                      ▼
                   [Proof]
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│ fp-zk-verifier (Proof Verification)                     │
│ • Groth16 verifier                                      │
│ • VERIFIES proofs on-chain                              │
│ • USE: Runtime only                                     │
└─────────────────────────────────────────────────────────┘
```

### Why 3 separate crates?

| Crate | Purpose | Runs where | Size | Dependencies |
|-------|---------|------------|------|--------------|
| **fp-zk-primitives** | Fast native crypto | Wallet + Runtime + Tests | Small | Minimal (arkworks) |
| **fp-zk-circuits** | Generate proofs | Wallet + CLI (off-chain) | Large | Heavy (R1CS, constraint system) |
| **fp-zk-verifier** | Verify proofs | Runtime (on-chain) | Small | Minimal (Groth16 only) |

**Key insight**: Runtime doesn't need R1CS dependencies (heavy). It only verifies proofs, not generates them.

## Gadgets vs Native Primitives

**Why do gadgets and native implementations coexist?**

```rust
// NATIVE (fp-zk-primitives) - Wallet computes commitment
use fp_zk_primitives::crypto::commitment::create_commitment;
let commitment = create_commitment(value, blinding); // Direct result

// GADGET (fp-zk-circuits) - Circuit generates R1CS constraints
use fp_zk_circuits::gadgets::commitment::commitment_gadget;
let commitment_var = commitment_gadget(value_var, blinding_var); // Constraints

// Tests validate both produce the same result
assert_eq!(commitment, commitment_var.value());
```

| Aspect | Native (`fp-zk-primitives`) | Gadget (`fp-zk-circuits`) |
|--------|----------------------------|---------------------------|
| **Operation** | Computes result directly | Generates R1CS constraints |
| **Speed** | Fast (native Rust) | Slower (constraint building) |
| **Output** | Field element value | ConstraintSystem variable |
| **Use case** | Wallets, runtime checks | Inside ZK circuits (proof generation) |
| **Proof** | No proof generated | Creates provable computation |

## Module Structure

```
fp-zk-circuits/
├── gadgets/              # R1CS constraint gadgets
│   ├── poseidon.rs       # Poseidon hash (ZK-friendly)
│   ├── merkle.rs         # Merkle tree membership
│   └── commitment.rs     # Commitments and nullifiers
└── circuits/             # Complete ZK circuits
    ├── note.rs           # Note commitment circuit
    └── transfer.rs       # Private transfer circuit (2 inputs → 2 outputs)
```

## Usage

### Creating a Transfer Circuit

```rust
use fp_zk_circuits::circuits::transfer::{TransferCircuit, TransferWitness};
use fp_zk_circuits::circuits::note::Note;
use ark_bn254::Fr;

// Create input notes (what you're spending)
let input_note1 = Note::new(1000, 0, owner_pubkey, blinding1);
let input_note2 = Note::new(500, 0, owner_pubkey, blinding2);

// Create output notes (where funds go)
let output_note1 = Note::new(1200, 0, recipient_pubkey, blinding3);
let output_note2 = Note::new(300, 0, change_pubkey, blinding4);

// Create witness with private data
let witness = TransferWitness::new(
    [input_note1, input_note2],
    [spending_key1, spending_key2],
    merkle_path_elements,   // Merkle proofs for inputs
    merkle_path_indices,
    [output_note1, output_note2],
);

// Create circuit with public input (Merkle root)
let circuit = TransferCircuit::new(witness, merkle_root);

// Generate proof (requires `proving` feature + trusted setup)
use ark_groth16::Groth16;
let proof = Groth16::prove(&proving_key, circuit, &mut rng)?;
```

### Using Gadgets Directly

```rust
use fp_zk_circuits::gadgets::poseidon::poseidon_hash_2;
use fp_zk_circuits::gadgets::merkle::merkle_tree_verifier;
use fp_zk_circuits::gadgets::commitment::commitment_gadget;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;

let cs = ConstraintSystem::new_ref();

// Allocate witness variables (private inputs)
let value = FpVar::new_witness(cs.clone(), || Ok(Fr::from(100)))?;
let blinding = FpVar::new_witness(cs.clone(), || Ok(Fr::from(123)))?;

// Generate constraints for Poseidon hash
let hash = poseidon_hash_2(cs.clone(), &[value, blinding])?;

// Generate constraints for Merkle proof
let root = merkle_tree_verifier(cs.clone(), &leaf, &path, &indices)?;

// Generate constraints for commitment
let commitment = commitment_gadget(cs.clone(), &value, &blinding)?;
```

## Features

- `std` (default): Standard library support
- `proving`: Enables proof generation (adds `ark-groth16`, `ark-snark`)

```toml
[dependencies]
fp-zk-circuits = { version = "0.1", default-features = false }

# For proof generation (wallets, CLI tools)
fp-zk-circuits = { version = "0.1", features = ["std", "proving"] }

# For no_std circuit development (testing gadgets only)
fp-zk-circuits = { version = "0.1", default-features = false }
```

## Testing

```bash
# Run all tests
cargo test

# Run with proving feature
cargo test --features proving

# Check without proving (faster)
cargo check

# Verify no warnings
cargo clippy -- -D warnings
```

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `fp-zk-primitives` | Native crypto primitives (for validation) |
| `fp-zk-verifier` | Shared types and constants |
| `ark-r1cs-std` | R1CS constraint system stdlib |
| `ark-relations` | Constraint relations framework |
| `ark-bn254` | BN254 elliptic curve |
| `ark-groth16` (optional) | Groth16 proving system |
| `poseidon-ark` | Poseidon hash (circomlib compatible) |

## When to use this crate

**Use fp-zk-circuits when:**
- Generating proofs off-chain (wallet, CLI)
- Developing new circuits
- Testing gadget implementations
- Creating proof servers

**Don't use fp-zk-circuits when:**
- Building runtime (use `fp-zk-verifier` instead)
- Just verifying proofs (use `fp-zk-verifier`)
- Computing native crypto (use `fp-zk-primitives`)

## Security Considerations

### Trusted Setup

Circuits require a trusted setup (Powers of Tau ceremony):
```bash
# Generate proving/verifying keys (done once per circuit)
snarkjs groth16 setup circuit.r1cs pot.ptau circuit.zkey
```

### Field Element Constraints

All values must be valid BN254 field elements:
```rust
// Valid: values < BN254 modulus
let valid = Fr::from(12345);

// Invalid: will wrap/reduce
let invalid = Fr::from_be_bytes_mod_order(&[0xFF; 32]);
```

## Performance

| Operation | Constraints | Proof Time | Verification Time |
|-----------|-------------|------------|-------------------|
| Poseidon hash (2 inputs) | ~150 | <1ms | <1ms |
| Merkle proof (depth 20) | ~3000 | ~5ms | <1ms |
| Transfer circuit | ~8000 | ~100ms | ~10ms |
| Unshield circuit | ~5000 | ~60ms | ~8ms |

*Benchmarked on M1 Mac with BN254 curve*

## Related Crates

- **fp-zk-primitives**: Native cryptographic primitives
- **fp-zk-verifier**: On-chain proof verification
- **pallet-shielded-pool**: Runtime pallet using these circuits

## License

Licensed under Apache 2.0 or GPL-3.0.