# pallet-zk-verifier

A FRAME pallet for verifying Zero-Knowledge proofs on-chain with Clean Architecture.

## Overview

This pallet provides efficient Groth16 proof verification for privacy-preserving transactions in the Orbinum network. It manages verification keys per circuit and tracks verification statistics.

## Key Features

- **Groth16 Verification**: Sub-10ms proof verification on-chain
- **Circuit Management**: Register and manage verification keys per circuit
- **Statistics Tracking**: Monitor verification counts and success rates
- **Clean Architecture**: Domain-driven design with clear separation of concerns
- **Extensible**: Support for multiple proof systems (Groth16, PLONK, Halo2)

## Supported Circuits

| Circuit | Description | Public Inputs |
|---------|-------------|---------------|
| `transfer` | Private transfer (2 inputs → 2 outputs) | `merkle_root`, `nullifier×2`, `commitment×2` |
| `unshield` | Withdraw from shielded pool | `merkle_root`, `nullifier`, `amount`, `recipient`, `asset_id` |
| `disclosure` | Selective disclosure of note data | `commitment`, `revealed_value`, `revealed_asset_id`, `revealed_owner_hash` |
| `private_link` | ZK proof of cross-chain address ownership | `commitment`, `call_hash_fe` |

## Public API

The pallet exposes a single trait for integration with other pallets:

```rust
pub trait ZkVerifierPort {
    fn verify_transfer_proof(
        proof: &[u8],
        merkle_root: &[u8; 32],
        nullifiers: &[[u8; 32]],
        commitments: &[[u8; 32]],
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

    fn verify_unshield_proof(
        proof: &[u8],
        merkle_root: &[u8; 32],
        nullifier: &[u8; 32],
        amount: u128,
        recipient: &[u8; 32],
        asset_id: u32,
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

    fn verify_disclosure_proof(
        proof: &[u8],
        public_signals: &[u8],
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

    fn batch_verify_disclosure_proofs(
        proofs: &[Vec<u8>],
        public_signals: &[Vec<u8>],
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

    /// Verifica una prueba ZK de private link (cross-chain identity).
    /// - `commitment`: Poseidon(Poseidon(chain_id_fe, address_fe), blinding_fe)
    /// - `call_hash_fe`: hash del RuntimeCall que se está autorizando
    fn verify_private_link_proof(
        proof: &[u8],
        commitment: &[u8; 32],
        call_hash_fe: &[u8; 32],
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;
}
```

## External Dependencies

### Required Primitives

This pallet depends on the following cryptographic primitives:

- **[orbinum-zk-verifier](../../primitives/zk-verifier)** (v0.4.0): Groth16 verification implementation
  — incluye VKs embebidas para `transfer`, `unshield`, `disclosure` y `private_link`
- **[orbinum-zk-core](../../primitives/zk-core)** (v0.5.0): ZK primitives (Commitment, Nullifier, Note)

### FRAME Dependencies

- `frame-support`: Pallet infrastructure
- `frame-system`: System primitives
- `sp-runtime`: Runtime types
- `sp-std`: Substrate standard library

### Development Dependencies

- **criterion** (v0.5): Performance benchmarking
- **hex-literal**: Test data encoding

## Usage

### Runtime Integration

Add to your `runtime/Cargo.toml`:

```toml
[dependencies]
pallet-zk-verifier = { path = "../frame/zk-verifier", default-features = false }

[features]
std = [
    "pallet-zk-verifier/std",
]
```

Add to your `runtime/src/lib.rs`:

```rust
impl pallet_zk_verifier::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Runtime>;
}

construct_runtime! {
    pub enum Runtime {
        // ...
        ZkVerifier: pallet_zk_verifier,
    }
}
```

### Using in Other Pallets

```rust
use pallet_zk_verifier::ZkVerifierPort;

// Verify a shielded transfer proof
let is_valid = T::ZkVerifier::verify_transfer_proof(
    &proof,
    &merkle_root,
    &nullifiers,
    &commitments,
    None,
)?;

// Verify a private link proof (pallet-account-mapping)
let is_valid = T::ZkVerifier::verify_private_link_proof(
    &proof,
    &commitment,
    &call_hash_fe,
    None,
)?;
```

## Extrinsics

### `register_verification_key`

Register a verification key for a specific circuit.

**Parameters:**
- `circuit_id`: Unique identifier for the circuit
- `vk_bytes`: Serialized verification key
- `proof_system`: Proof system type (Groth16, PLONK, Halo2)

**Required:** Root origin

### `verify_proof`

Verify a zero-knowledge proof.

**Parameters:**
- `circuit_id`: Circuit identifier
- `proof`: Serialized proof
- `public_inputs`: Public inputs for verification

**Returns:** Event indicating success or failure

## Storage

- `VerificationKeys`: Registered verification keys per circuit
- `Statistics`: Verification statistics per circuit (total, successful, failed)

## Events

- `VerificationKeyRegistered`: New verification key registered
- `ProofVerified`: Proof successfully verified
- `ProofVerificationFailed`: Proof verification failed

## Benchmarking

The pallet includes two types of benchmarks:

### Development (Criterion)
```bash
cd frame/zk-verifier
./benches/run.sh criterion-fast
```

### Production (FRAME Weights)
```bash
cargo build --release --features runtime-benchmarks
./benches/run.sh frame
```

See [BENCHMARKING.md](BENCHMARKING.md) for details.

## Architecture

The pallet follows Clean Architecture principles:

```
├── domain/          # Business logic (ports, entities)
├── application/     # Use cases
├── infrastructure/  # FRAME integration, adapters
│   ├── adapters.rs  # VK adapters: Transfer, Unshield, Disclosure, PrivateLink
│   └── services/
│       └── groth16_verifier.rs  # Implementación de ZkVerifierPort
└── presentation/    # Extrinsics, events
```

### VK Adapters

Cada circuito tiene su propio adapter en `infrastructure/adapters.rs` que carga
la verification key embebida desde `primitives/zk-verifier`:

| Adapter | Circuito | Método |
|---------|----------|--------|
| `TransferVkAdapter` | transfer | `get_transfer_vk()` |
| `UnshieldVkAdapter` | unshield | `get_unshield_vk()` |
| `DisclosureVkAdapter` | disclosure | `get_disclosure_vk()` |
| `PrivateLinkVkAdapter` | private_link | `get_private_link_vk()` |

## Changelog

### v0.3.0
- Implementación de producción de `verify_private_link_proof` con `PrivateLinkVkAdapter`
- Añadido `PrivateLinkVkAdapter` en `infrastructure/adapters.rs`
- Export de `get_private_link_vk` desde `primitives/zk-verifier`

### v0.2.0
- Soporte para `verify_disclosure_proof` y `batch_verify_disclosure_proofs`
- Circuito `disclosure` con VK embebida

### v0.1.0
- Verificación Groth16 inicial (`transfer`, `unshield`)
- Clean Architecture, adapters, ProofValidator trait

## License

Dual-licensed: Apache 2.0 / GPL-3.0-or-later
