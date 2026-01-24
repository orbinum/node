# fp-zk-verifier

Groth16 proof verifier primitives for Zero-Knowledge circuits in Orbinum Network.

## Overview

This crate provides the core verification infrastructure for validating Zero-Knowledge proofs on-chain. It is designed to be used by:

- **Runtime**: Verify ZK proofs in extrinsics (transfer, unshield operations)
- **Pallets**: Integrate proof verification into custom logic
- **Tests**: Validate proof generation and verification workflows

## Architecture (3 Layers + VK Registry)

```
┌─────────────────────────────────────────────────────────────┐
│                    ZK VERIFIER                              │
│                    (3-Layer Architecture)                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 1: CORE (Foundational Types)                        │
│  ────────────────────────────────                           │
│  • types.rs                                                 │
│    - Proof: Groth16 proof structure                        │
│    - VerifyingKey: Circuit verification key                │
│    - PublicInputs: Public circuit inputs                   │
│  • constants.rs                                             │
│    - CIRCUIT_ID_TRANSFER = 1                               │
│    - CIRCUIT_ID_UNSHIELD = 2                               │
│    - TRANSFER_PUBLIC_INPUTS = 5                            │
│    - UNSHIELD_PUBLIC_INPUTS = 4                            │
│    - BASE_VERIFICATION_COST, PER_INPUT_COST                │
│  • error.rs                                                 │
│    - VerifierError: Error types                            │
│                                                             │
│  Layer 2: CRYPTO (Cryptographic Verification)              │
│  ─────────────────────────────────────────                  │
│  • groth16.rs: Proof verification                          │
│    - Groth16Verifier::verify(vk, inputs, proof)            │
│    - estimate_verification_cost(input_count)               │
│  • utils.rs: Field conversions                             │
│    - bytes_to_field_elements(bytes)                        │
│    - field_elements_to_bytes(elements)                     │
│                                                             │
│  Layer 3: COMPAT (Compatibility & Interoperability)        │
│  ───────────────────────────────────────────────────────    │
│  • snarkjs.rs: SnarkJS format support                      │
│    - parse_proof_from_snarkjs(json)                        │
│    - parse_public_inputs_from_snarkjs(json)                │
│                                                             │
│  VK Registry (Verification Keys)                            │
│  ────────────────────────────────                           │
│  • vk/transfer.rs: Transfer circuit VK (5 inputs)          │
│  • vk/unshield.rs: Unshield circuit VK (4 inputs)          │
│  • vk/registry.rs: Runtime lookup by circuit ID            │
│    - get_vk_by_circuit_id(id)                              │
│    - get_public_input_count(id)                            │
│    - validate_public_input_count(id, count)                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Usage

### Imports

**DO NOT use wildcards (`*`)**. Import specific functions with full paths:

```rust
// CORRECT - Explicit paths
use fp_zk_verifier::core::types::{Proof, VerifyingKey, PublicInputs};
use fp_zk_verifier::core::constants::{CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD};
use fp_zk_verifier::crypto::groth16::Groth16Verifier;
use fp_zk_verifier::vk::registry::{get_vk_by_circuit_id, validate_public_input_count};
use fp_zk_verifier::compat::snarkjs::{parse_proof_from_snarkjs, parse_public_inputs_from_snarkjs};

// INCORRECT - Don't use wildcards
use fp_zk_verifier::crypto::*;
use fp_zk_verifier::vk::*;
```

### Basic Verification

```rust
use fp_zk_verifier::core::constants::CIRCUIT_ID_TRANSFER;
use fp_zk_verifier::crypto::groth16::Groth16Verifier;
use fp_zk_verifier::vk::registry::get_vk_by_circuit_id;

// Get verification key for transfer circuit
let vk = get_vk_by_circuit_id(CIRCUIT_ID_TRANSFER)?;

// Verify proof
let result = Groth16Verifier::verify(&vk, &public_inputs, &proof);
assert!(result.is_ok());
```

### Using VK Registry

```rust
use fp_zk_verifier::core::constants::{CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD};
use fp_zk_verifier::vk::registry::{
    get_vk_by_circuit_id, 
    get_public_input_count,
    validate_public_input_count
};

// Dynamic VK lookup
let circuit_id = CIRCUIT_ID_TRANSFER;
let vk = get_vk_by_circuit_id(circuit_id)?;

// Get expected input count
let expected = get_public_input_count(circuit_id)?;
assert_eq!(expected, 5); // Transfer has 5 inputs

// Validate inputs before verification
validate_public_input_count(circuit_id, public_inputs.len())?;
```

### SnarkJS Integration

```rust
use fp_zk_verifier::compat::snarkjs::{
    parse_proof_from_snarkjs,
    parse_public_inputs_from_snarkjs
};

// Parse proof from SnarkJS JSON
let snarkjs_proof = r#"{"pi_a": [...], "pi_b": [...], "pi_c": [...]}"#;
let proof = parse_proof_from_snarkjs(snarkjs_proof)?;

// Parse public inputs
let snarkjs_inputs = r#"["123", "456", ...]"#;
let inputs = parse_public_inputs_from_snarkjs(snarkjs_inputs)?;
```

### Cost Estimation

```rust
use fp_zk_verifier::crypto::groth16::Groth16Verifier;

// Estimate verification cost (for fee calculation)
let input_count = 5; // Transfer circuit
let cost = Groth16Verifier::estimate_verification_cost(input_count);
```

## Features

- `std` (default): Enable standard library support
- `substrate`: Enable Substrate runtime integration (sp-core, sp-runtime, sp-std)

```toml
[dependencies]
fp-zk-verifier = { version = "0.1", default-features = false }

# For no_std runtime
fp-zk-verifier = { version = "0.1", default-features = false, features = ["substrate"] }
```

## Testing

```bash
# Run all tests
cargo test --features std

# Run specific test file
cargo test --test vk_tests

# Run with output
cargo test -- --nocapture

# Check compilation
cargo check --all-features
```

### Test Organization

```
tests/
├── crypto_tests.rs        # Groth16 verification and utils (6 tests)
├── vk_tests.rs            # VK registry and structure (11 tests)
└── snarkjs_compat_tests.rs  # SnarkJS parsing (4 tests)
```

## Security Considerations

### Hardcoded Verification Keys

- **Transfer VK**: Hardcoded in binary for CIRCUIT_ID_TRANSFER (1)
- **Unshield VK**: Hardcoded in binary for CIRCUIT_ID_UNSHIELD (2)
- Keys are generated from trusted setup (Powers of Tau ceremony)
- **DO NOT** modify VK bytes without proper ceremony

### Public Input Validation

```rust
use fp_zk_verifier::vk::registry::validate_public_input_count;

// Always validate input count before verification
validate_public_input_count(circuit_id, inputs.len())?;
```

### Circuit IDs

- Circuit IDs must be consistent across:
  - Runtime (this crate)
  - Wallet clients
  - Off-chain proof generators
- Changing IDs requires coordinated upgrade

## Performance

| Operation | Time (on-chain) | Gas Cost |
|-----------|-----------------|----------|
| Transfer verification | ~8-10ms | ~100k |
| Unshield verification | ~6-8ms | ~80k |
| VK lookup | <1ms | ~1k |
| Input validation | <1ms | ~500 |

*Benchmarked on Substrate parachain with BN254 curve*

## Integration Example

```rust
use frame_support::pallet_prelude::*;
use fp_zk_verifier::core::constants::CIRCUIT_ID_TRANSFER;
use fp_zk_verifier::core::types::{Proof, PublicInputs};
use fp_zk_verifier::crypto::groth16::Groth16Verifier;
use fp_zk_verifier::vk::registry::{get_vk_by_circuit_id, validate_public_input_count};

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::weight(100_000)]
    pub fn verify_transfer_proof(
        origin: OriginFor<T>,
        proof: Proof,
        public_inputs: PublicInputs,
    ) -> DispatchResult {
        ensure_signed(origin)?;
        
        // Validate input count
        validate_public_input_count(CIRCUIT_ID_TRANSFER, public_inputs.len())
            .map_err(|_| Error::<T>::InvalidInputCount)?;
        
        // Get verification key
        let vk = get_vk_by_circuit_id(CIRCUIT_ID_TRANSFER)
            .map_err(|_| Error::<T>::InvalidCircuitId)?;
        
        // Verify proof
        Groth16Verifier::verify(&vk, &public_inputs, &proof)
            .map_err(|_| Error::<T>::ProofVerificationFailed)?;
        
        Ok(())
    }
}
```

## Development

### Adding New Circuits

1. Generate VK from trusted setup:
   ```bash
   snarkjs groth16 setup circuit.r1cs pot.ptau circuit.zkey
   snarkjs zkey export verificationkey circuit.zkey vk.json
   ```

2. Convert to Rust:
   ```bash
   # Use scripts/convert_vk.rs from circuits/ directory
   cargo run --bin convert_vk -- vk.json > vk_bytes.txt
   ```

3. Create new VK module:
   ```rust
   // src/vk/new_circuit.rs
   pub const CIRCUIT_ID: u8 = 3;
   pub const PUBLIC_INPUT_COUNT: usize = 6;
   
   pub fn get_vk() -> VerifyingKey {
       // ... paste VK bytes
   }
   ```

4. Register in `vk/registry.rs`:
   ```rust
   pub fn get_vk_by_circuit_id(id: u8) -> Result<VerifyingKey, VerifierError> {
       match id {
           CIRCUIT_ID_TRANSFER => Ok(transfer::get_vk()),
           CIRCUIT_ID_UNSHIELD => Ok(unshield::get_vk()),
           3 => Ok(new_circuit::get_vk()), // Add here
           _ => Err(VerifierError::InvalidCircuitId(id)),
       }
   }
   ```

## References

- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [BN254 Curve](https://github.com/arkworks-rs/curves/tree/master/bn254)
- [SnarkJS Documentation](https://github.com/iden3/snarkjs)
- [Arkworks Library](https://github.com/arkworks-rs/groth16)

## License

Licensed under Apache 2.0 or GPL-3.0.