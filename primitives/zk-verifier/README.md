# orbinum-zk-verifier

Groth16 (BN254) verification primitive for Orbinum.

This crate implements a 3-layer clean architecture (`domain`, `application`, `infrastructure`) and does not manage on-chain verification key storage. VK resolution and versioning are handled by the `frame/zk-verifier` pallet.

## Architecture

- `domain/`
  - ports (`VerifierPort`), services (`ProofValidator`), and value objects (`Proof`, `VerifyingKey`, `PublicInputs`, `VerifierError`).
- `application/`
  - use cases (`VerifyProofUseCase`) and output DTOs.
- `infrastructure/`
  - concrete implementation (`Groth16Verifier`) and adapters (`snarkjs_adapter`, `std` feature only).

## Basic Usage

```rust
use orbinum_zk_verifier::{
    application::use_cases::VerifyProofUseCase,
    domain::value_objects::{Proof, PublicInputs, VerifyingKey},
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

assert!(result.is_ok());
```

## Substrate Integration

```toml
[dependencies]
orbinum-zk-verifier = { version = "0.6.2", default-features = false, features = ["substrate"] }
```

## Supported Circuits

| Circuit ID | Name | Public Inputs |
|---|---|---|
| 1 | transfer | 5 |
| 2 | unshield | 5 |
| 4 | disclosure | 4 |
| 5 | private_link | 2 |

## Features

- `std` (default): enables standard-library utilities and `snarkjs` adapters.
- `substrate`: enables SCALE codec integration (`parity-scale-codec`, `scale-info`) for runtime use.

## Design Notes

- `Groth16Verifier` implements `VerifierPort` to decouple use cases from the concrete cryptographic library.
- Structural validation (input count and minimum proof/VK size) is executed in the domain layer before cryptographic verification.
- `batch_verify` is available at the infrastructure layer for optimization scenarios.

## License

Dual: Apache-2.0 OR GPL-3.0-or-later.
