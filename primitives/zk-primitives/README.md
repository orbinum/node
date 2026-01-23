# fp-zk-primitives

Native cryptographic primitives for Zero-Knowledge proofs in Orbinum Network.

## 📖 Overview

This crate provides the fundamental building blocks for privacy-preserving transactions, without the heavy R1CS constraint system dependencies. It is designed to be used by:

- **Wallets**: Create notes, compute commitments, verify Merkle proofs
- **Runtime**: Validate public inputs, check Merkle roots
- **Tests**: Unit testing without full circuit dependencies

## 🏗️ Architecture (3 Layers)

```
┌─────────────────────────────────────────────────────────────┐
│                    ZK PRIMITIVES                            │
│                    (3-Layer Architecture)                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 1: CORE (Foundational Types)                        │
│  ────────────────────────────────                           │
│  • types.rs                                                 │
│    - Bn254Fr: Base field element                           │
│    - Commitment: Strong type (prevents confusion)          │
│    - Nullifier: Strong type (prevents confusion)           │
│    - SpendingKey: Strong type with security semantics      │
│  • constants.rs                                             │
│    - DEFAULT_TREE_DEPTH, MAX_TREE_DEPTH                    │
│    - NATIVE_ASSET_ID, FIELD_ELEMENT_SIZE                   │
│    - Domain separators (COMMITMENT_DOMAIN, etc.)           │
│  • error.rs                                                 │
│    - PrimitiveError: Error types                           │
│                                                             │
│  Layer 2: CRYPTO (Cryptographic Operations)                │
│  ──────────────────────────────────────                     │
│  • hash.rs: Poseidon hash (ZK-friendly)                    │
│    - poseidon_hash_2, poseidon_hash_4                      │
│    - poseidon_hash (generic 1-12 inputs)                   │
│  • commitment.rs: Commitments and nullifiers               │
│    - create_commitment: Create note commitment             │
│    - compute_nullifier: Generate nullifier for spending    │
│  • merkle.rs: Merkle proof verification                    │
│    - compute_merkle_root: Compute root from leaf           │
│    - verify_merkle_proof: Verify membership proof          │
│    - compute_empty_root: Empty tree at any depth           │
│                                                             │
│  Layer 3: MODELS (High-Level Abstractions)                 │
│  ───────────────────────────────────────                    │
│  • note.rs: Private note representation                    │
│    - Note { value, asset_id, owner_pubkey, blinding }      │
│    - note.commitment() → Commitment                        │
│    - note.nullifier(&key) → Nullifier                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Usage

### Imports

**DO NOT use wildcards (`*`)**. Import specific functions with full paths:

```rust
// ✅ CORRECT - Explicit paths
use fp_zk_primitives::core::types::{Commitment, Nullifier, SpendingKey};
use fp_zk_primitives::core::constants::{DEFAULT_TREE_DEPTH, NATIVE_ASSET_ID};
use fp_zk_primitives::crypto::commitment::{create_commitment, compute_nullifier};
use fp_zk_primitives::crypto::hash::{poseidon_hash_2, poseidon_hash_4};
use fp_zk_primitives::crypto::merkle::verify_merkle_proof;
use fp_zk_primitives::models::note::Note;

// ❌ INCORRECT - Don't use wildcards
use fp_zk_primitives::crypto::hash::*;
use fp_zk_primitives::core::*;
```

### Complete Example

```rust
use ark_bn254::Fr as Bn254Fr;
use fp_zk_primitives::core::types::{Commitment, SpendingKey};
use fp_zk_primitives::core::constants::NATIVE_ASSET_ID;
use fp_zk_primitives::crypto::commitment::compute_nullifier;
use fp_zk_primitives::crypto::merkle::verify_merkle_proof;
use fp_zk_primitives::models::note::Note;

// 1. Create a private note
let note = Note::new(
    100,                    // value: 100 tokens
    NATIVE_ASSET_ID,        // asset_id: native token
    owner_pubkey,           // Owner's public key
    blinding                // Random blinding factor
);

// 2. Get commitment (stored in Merkle tree)
let commitment: Commitment = note.commitment();

// 3. Compute nullifier (when spending the note)
let spending_key = SpendingKey::new(Bn254Fr::from(12345u64));
let nullifier = note.nullifier(&spending_key);

// 4. Verify Merkle proof (prove that note exists in tree)
let is_valid = verify_merkle_proof(
    &commitment,
    &path_elements,
    &path_indices,
    &merkle_root
);
```

## 🔑 Strong Types

This crate uses the **new-type pattern** to prevent type confusion at compile time:

```rust
// ✅ Type safety
let commitment = Commitment::new(field_element);
let nullifier = Nullifier::new(field_element);
let spending_key = SpendingKey::new(field_element);

// ❌ This does NOT compile (compile-time error)
// let result = compute_nullifier(&nullifier, &commitment);  // Wrong order
```

## 🧪 Testing

The primitive includes **120 integration tests** organized by functionality:

```bash
# Run all tests
cargo test --tests

# Tests by module
cargo test --test core_types_tests       # 27 tests - Core types
cargo test --test core_constants_tests   # 11 tests - Constants
cargo test --test core_error_tests       # 14 tests - Errors
cargo test --test hash_tests             # 11 tests - Poseidon hash
cargo test --test commitment_tests       # 13 tests - Commitments
cargo test --test merkle_tests           # 16 tests - Merkle proofs
cargo test --test note_tests             # 16 tests - Notes
cargo test --test integration_tests      # 16 tests - Complete workflows
```

## 🔧 Features

- **`std`** (default): Enables standard library features
- **`substrate`**: Enables `parity_scale_codec` and `scale_info` derives

```toml
# Cargo.toml
[dependencies]
fp-zk-primitives = { version = "0.1.0", default-features = true }

# For no-std environments
fp-zk-primitives = { version = "0.1.0", default-features = false }

# For Substrate runtime
fp-zk-primitives = { version = "0.1.0", features = ["substrate"] }
```

## 📐 Compatibility

All hash functions are **compatible with circomlib/iden3**, ensuring that values computed here match those from Circom circuits:

- ✅ Poseidon hash: Compatible with `circomlib/poseidon.circom`
- ✅ Merkle tree: Compatible with `circomlib/smt.circom`
- ✅ Commitment scheme: Same format as ZK circuits

## 📊 File Structure

```
zk-primitives/
├── src/
│   ├── lib.rs                  # Entry point, documentation
│   ├── core/
│   │   ├── mod.rs             # Core module (no re-exports)
│   │   ├── types.rs           # Strong types (Commitment, Nullifier, etc.)
│   │   ├── constants.rs       # System constants
│   │   └── error.rs           # Error types
│   ├── crypto/
│   │   ├── mod.rs             # Crypto module (no re-exports)
│   │   ├── hash.rs            # Poseidon hash (circomlib compatible)
│   │   ├── commitment.rs      # Commitments and nullifiers
│   │   └── merkle.rs          # Merkle proof verification
│   └── models/
│       ├── mod.rs             # Models module (no re-exports)
│       └── note.rs            # Private note (high-level)
├── tests/                      # 120 integration tests
│   ├── core_types_tests.rs
│   ├── core_constants_tests.rs
│   ├── core_error_tests.rs
│   ├── hash_tests.rs
│   ├── commitment_tests.rs
│   ├── merkle_tests.rs
│   ├── note_tests.rs
│   └── integration_tests.rs
├── Cargo.toml
└── README.md                   # This file
```

## 🔒 Security

- **Strong types**: Prevents type confusion at compile time
- **No wildcards**: Explicit imports for better traceability
- **Clean architecture**: 3 well-defined layers (core → crypto → models)
- **Exhaustive tests**: 120 tests covering all functionality
- **Verified compatibility**: Hash functions compatible with circomlib

## 🌐 Usage in Orbinum Network

This primitive is used by:

1. **fp-zk-verifier**: Groth16 proof verification in runtime
2. **fp-zk-circuits**: ZK proof generation (R1CS circuits)
3. **orbinum-wallet-cli**: CLI wallet for creating private transactions
4. **pallet-shielded-pool**: Substrate pallet for the shielded pool

## 📝 Changelog

### v0.1.0 (Initial)
- 3-layer architecture
- Strong types (new-type pattern) for compile-time safety
- 120 integration tests in `tests/` directory

## 📄 License

Dual-licensed: Apache-2.0 / GPL-3.0
