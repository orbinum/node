# orbinum-zk-verifier

[![crates.io](https://img.shields.io/crates/v/orbinum-zk-verifier.svg)](https://crates.io/crates/orbinum-zk-verifier)
[![Documentation](https://docs.rs/orbinum-zk-verifier/badge.svg)](https://docs.rs/orbinum-zk-verifier)

On-chain Zero-Knowledge proof verification for Orbinum Network using Groth16 over BN254.

## Features

- **Fast verification**: ~8ms on-chain for private transfers
- **Small proofs**: ~200 bytes
- **no_std compatible**: Suitable for Substrate runtimes
- **Embedded verification keys**: No external storage needed
- **SnarkJS compatible**: Works with circom circuits

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
orbinum-zk-verifier = { version = "0.2", default-features = false }
```

### Basic Verification

```rust
use orbinum_zk_verifier::{
    infrastructure::verification::Groth16Verifier,
    domain::value_objects::{Proof, PublicInputs, VerifyingKey},
};

// Load verification key (embedded or from storage)
let vk = get_transfer_vk();

// Prepare inputs
let public_inputs = PublicInputs::new(vec![
    merkle_root,
    nullifier1,
    nullifier2,
    commitment1,
    commitment2,
]);

// Verify proof
let verifier = Groth16Verifier::new();
let result = verifier.verify(&vk, &public_inputs, &proof);

assert!(result.is_ok());
```

### With Use Case Pattern

```rust
use orbinum_zk_verifier::{
    application::use_cases::VerifyProofUseCase,
    infrastructure::verification::Groth16Verifier,
};

let verifier = Groth16Verifier::new();
let use_case = VerifyProofUseCase::new(verifier);

let result = use_case.execute(
    &vk,
    &public_inputs,
    &proof,
    expected_input_count,
);
```

### Substrate Runtime Integration

```toml
[dependencies]
orbinum-zk-verifier = { version = "0.2", default-features = false, features = ["substrate"] }
```

```rust
// In your pallet
use orbinum_zk_verifier::infrastructure::storage::verification_keys::get_vk_by_circuit_id;

#[pallet::call]
impl<T: Config> Pallet<T> {
    pub fn verify_proof(
        origin: OriginFor<T>,
        circuit_id: u8,
        proof: Proof,
        public_inputs: PublicInputs,
    ) -> DispatchResult {
        let vk = get_vk_by_circuit_id(circuit_id)?;
        let verifier = Groth16Verifier::new();
        verifier.verify(&vk, &public_inputs, &proof)?;
        Ok(())
    }
}
```

## Supported Circuits

| Circuit ID | Name | Public Inputs | Description |
|------------|------|---------------|-------------|
| 1 | Transfer | 5 | Private transfer (2→2) |
| 2 | Unshield | 4 | Withdrawal to public |
| 3 | Disclosure | 3 | Selective disclosure |

## Features Flags

- `std` (default): Standard library support
- `substrate`: Substrate runtime integration (SCALE codec, TypeInfo)

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Verify Transfer | ~8ms | 5 public inputs |
| Verify Unshield | ~6ms | 4 public inputs |
| Prepare VK | ~2ms | Cacheable |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE2) or [GPL v3](LICENSE-GPL3) at your option.
