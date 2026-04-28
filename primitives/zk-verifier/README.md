# orbinum-zk-verifier

Groth16 (BN254) proof verification primitive for Orbinum Network.

This crate handles the cryptographic verification layer only. On-chain VK storage,
versioning, and circuit dispatch are managed by `frame/zk-verifier`.

## Modules

| Module | Contents |
|---|---|
| `types` | `Proof`, `VerifyingKey`, `PublicInputs`, `VerifierError`, circuit constants |
| `verifier` | `Groth16Verifier` — static `verify`, `verify_with_prepared_vk`, `batch_verify` |
| `field_utils` | `bytes_to_field`, `field_to_bytes`, `field_to_u64`, `u64_to_field` |
| `snarkjs` | `parse_proof_from_snarkjs`, `parse_public_inputs_from_snarkjs` (`std` only) |

## Features

| Feature | Description | Default |
|---|---|---|
| `std` | Standard library + snarkjs JSON adapters | ✓ |
| `substrate` | SCALE codec (`parity-scale-codec`, `scale-info`) | — |

## Usage

### Single proof

```rust
use orbinum_zk_verifier::{Groth16Verifier, Proof, PublicInputs, VerifyingKey};

let result = Groth16Verifier::verify(&vk, &public_inputs, &proof);
assert!(result.is_ok());
```

### Optimized — pre-prepared VK

```rust
use orbinum_zk_verifier::{Groth16Verifier, VerifyingKey};

// Prepare once, reuse for every verification call.
let pvk = vk.prepare()?;
let result = Groth16Verifier::verify_with_prepared_vk(&pvk, &public_inputs, &proof);
```

### Batch verification

```rust
use orbinum_zk_verifier::Groth16Verifier;

// All proofs must belong to the same circuit (same VK).
let ok = Groth16Verifier::batch_verify(&vk, &all_inputs, &proofs)?;
```

### snarkjs adapter (std only)

```rust
use orbinum_zk_verifier::{parse_proof_from_snarkjs, parse_public_inputs_from_snarkjs, SnarkjsProofPoints};

let proof = parse_proof_from_snarkjs(SnarkjsProofPoints {
    a_x: "...", a_y: "...",
    b_x0: "...", b_x1: "...", b_y0: "...", b_y1: "...",
    c_x: "...", c_y: "...",
})?;

let inputs = parse_public_inputs_from_snarkjs(&["12345", "67890"])?;
```

## Supported circuits

| Circuit ID | Name | Public inputs |
|---|---|---|
| 1 | `transfer` | 7 |
| 2 | `unshield` | 6 |
| 4 | `disclosure` | 4 |
| 5 | `private_link` | 2 |

## Weight estimation

```rust
use orbinum_zk_verifier::Groth16Verifier;

// Returns BASE_VERIFICATION_COST + num_inputs * PER_INPUT_COST
let weight = Groth16Verifier::estimate_verification_cost(7);
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE2)
or [GPL v3](../../LICENSE-GPL3) at your option.

