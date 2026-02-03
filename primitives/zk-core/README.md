# orbinum-zk-core

Zero-Knowledge cryptographic primitives for privacy-preserving transactions.

## Features

- **Clean Architecture**: Domain → Application → Infrastructure layers
- **no_std compatible**: Full WASM runtime support
- **ZK-friendly**: Poseidon hash compatible with circomlib
- **Type safety**: Strong types prevent compile-time errors
- **88 tests**: Comprehensive test coverage

## Installation

```toml
[dependencies]
orbinum-zk-core = "0.2.0"

# For no-std/WASM
orbinum-zk-core = { version = "0.2.0", default-features = false }

# For Substrate with native optimizations
orbinum-zk-core = { version = "0.2.0", features = ["native-poseidon"] }
```

## Usage

```rust
use orbinum_zk_core::domain::entities::Note;
use orbinum_zk_core::domain::value_objects::{OwnerPubkey, Blinding, FieldElement};
use orbinum_zk_core::infrastructure::crypto::LightPoseidonHasher;

// Create note
let note = Note::new(
    1000,  // value
    1,     // asset_id
    OwnerPubkey::new(FieldElement::from_u64(12345)),
    Blinding::new(FieldElement::from_u64(67890)),
);

// Compute commitment
let hasher = LightPoseidonHasher;
let commitment = CommitmentService::new(&hasher).create_commitment(&note);
```

## Architecture

- **Domain**: Entities, value objects, services, ports
- **Application**: Use cases, DTOs
- **Infrastructure**: Crypto adapters, repositories

## License

Apache-2.0 OR GPL-3.0-or-later
