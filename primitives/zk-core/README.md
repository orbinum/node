# orbinum-zk-core

[![crates.io](https://img.shields.io/crates/v/orbinum-zk-core.svg)](https://crates.io/crates/orbinum-zk-core)
[![Documentation](https://docs.rs/orbinum-zk-core/badge.svg)](https://docs.rs/orbinum-zk-core)

Native zero-knowledge cryptographic primitives for Orbinum Network.

## Features

- **Fast native crypto**: Poseidon, commitments, nullifiers, Merkle trees
- **no_std compatible**: Full WASM runtime support
- **ZK-friendly**: Circomlib-compatible Poseidon hash
- **Type-safe**: Prevents common ZK errors at compile time
- **Well-tested**: 88 unit tests with 100% coverage

## Installation

```toml
[dependencies]
orbinum-zk-core = "0.2"

# For no-std/WASM
orbinum-zk-core = { version = "0.2", default-features = false }

# For Substrate with native optimizations (~3x faster)
orbinum-zk-core = { version = "0.2", features = ["native-poseidon"] }
```

## Usage

### Basic Note Operations

```rust
use orbinum_zk_core::{
    domain::entities::Note,
    domain::value_objects::{OwnerPubkey, Blinding, FieldElement},
    domain::services::CommitmentService,
    infrastructure::crypto::LightPoseidonHasher,
};

// Create a note
let note = Note::new(
    1000,  // value
    1,     // asset_id
    OwnerPubkey::new(FieldElement::from_u64(12345)),
    Blinding::new(FieldElement::from_u64(67890)),
);

// Generate commitment
let hasher = LightPoseidonHasher;
let service = CommitmentService::new(hasher);
let commitment = service.create_commitment(
    note.value(),
    note.asset_id(),
    note.owner_pubkey(),
    note.blinding(),
);
```

### Nullifier Generation

```rust
use orbinum_zk_core::{
    domain::services::NullifierService,
    domain::value_objects::SpendingKey,
};

let nullifier_service = NullifierService::new(hasher);
let spending_key = SpendingKey::new(FieldElement::from_u64(999));
let nullifier = nullifier_service.compute_nullifier(&commitment, &spending_key);
```

### Merkle Tree Operations

```rust
use orbinum_zk_core::domain::services::MerkleService;

let merkle_service = MerkleService::new(hasher);
let leaves = vec![commitment1, commitment2, commitment3];
let root = merkle_service.compute_root(&leaves);

// Generate Merkle proof
let proof = merkle_service.generate_proof(&leaves, 1);
assert!(merkle_service.verify_proof(&root, &leaves[1], &proof, 1));
```

## Key Concepts

- **Note**: UTXO-like primitive for private values
- **Commitment**: Hiding binding to note data (Poseidon hash)
- **Nullifier**: Prevents double-spending (derived from commitment + key)
- **Merkle Tree**: Accumulates commitments for membership proofs

## Poseidon Hash

Uses `light-poseidon-nostd` for circomlib compatibility:
- S-Box: x^5
- Full rounds: 8
- Partial rounds: 57 (for 2 inputs), 56 (for 4 inputs)
- ~300 constraints (vs ~25,000 for SHA-256)

## Performance

| Operation | Native | WASM | With native-poseidon |
|-----------|--------|------|----------------------|
| Commitment | 50μs | 150μs | 15μs |
| Nullifier | 40μs | 120μs | 12μs |
| Merkle Root (depth 20) | 1ms | 3ms | 300μs |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE2) or [GPL v3](LICENSE-GPL3) at your option.
