# pallet-zk-verifier

FRAME pallet for on-chain verification of Groth16 proofs in Orbinum.

## Status

MVP in active development. Production runtime verifies Groth16 proofs on BN254. PLONK and Halo2 are not active verification paths.

## What this pallet does

- Stores verification keys by `(circuit_id, version)`.
- Tracks active version per circuit.
- Verifies proofs on-chain through the `verify_proof` extrinsic.
- Exposes `ZkVerifierPort` — the cross-pallet interface used by `pallet-shielded-pool`.
- Tracks per-version verification statistics.

## Circuit IDs

| ID | Circuit |
|----|---------|
| `1` | transfer (2-in / 2-out UTXO) |
| `2` | unshield (pool withdrawal) |
| `3` | shield (reserved) |
| `4` | disclosure (selective disclosure) |
| `5` | private_link |

## Storage

- `VerificationKeys`: `(CircuitId, version) → raw VK bytes`.
- `ActiveCircuitVersion`: active version per circuit.
- `VerificationStats`: success/failure counters per `(circuit, version)`.

## Extrinsics

All extrinsics except `verify_proof` require `Root` origin.

| Extrinsic | Origin | Description |
|-----------|--------|-------------|
| `register_verification_key` | Root | Store a new VK for a circuit version |
| `set_active_version` | Root | Set the active version for a circuit |
| `remove_verification_key` | Root | Remove a non-active VK |
| `batch_register_verification_keys` | Root | Register multiple VKs in one call |
| `verify_proof` | Signed | Verify a proof and emit an event |

## ZkVerifierPort

Cross-pallet trait implemented by `Pallet<T>`. Used by `pallet-shielded-pool` for all proof verification:

```rust
pub trait ZkVerifierPort {
    fn verify_transfer_proof(
        proof: &[u8],
        merkle_root: &[u8; 32],
        nullifiers: &[[u8; 32]],
        commitments: &[[u8; 32]],
        asset_id: u32,
        fee: u128,
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

    fn verify_unshield_proof(
        proof: &[u8],
        merkle_root: &[u8; 32],
        nullifier: &[u8; 32],
        amount: u128,
        recipient: &[u8; 32],
        asset_id: u32,
        fee: u128,
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

    fn verify_disclosure_proof(
        proof: &[u8],
        public_signals: &[u8],  // exactly 76 bytes
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

    fn batch_verify_disclosure_proofs(
        proofs_and_signals: &[(&[u8], &[u8])],  // max 10, signals = 76 bytes each
        version: Option<u32>,
    ) -> Result<Vec<bool>, DispatchError>;

    fn verify_private_link_proof(
        proof: &[u8],
        commitment: &[u8; 32],
        link_nullifier: &[u8; 32],
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;
}
```

## Module layout

```
src/
  lib.rs          — pallet definition (Config, Storage, Events, Errors, extrinsics)
  port.rs         — ZkVerifierPort trait + Pallet<T> impl
  types.rs        — CircuitId, type aliases
  verifier.rs     — internal Groth16 dispatch logic
  encoding.rs     — public-input encoding helpers
  weights.rs      — WeightInfo trait + generated weights
```

The previous Clean Architecture layers (`domain/`, `application/`, `infrastructure/`, `presentation/`) have been removed. All logic lives in `lib.rs`, `port.rs`, and `verifier.rs`.

## Dependencies

- `orbinum-zk-verifier`: `Groth16Verifier`, `Proof`, `PublicInputs`, `VerifyingKey`.
- `orbinum-zk-core`: shared field types.
- FRAME: `frame-support`, `frame-system`, `sp-runtime`.

## Testing

```bash
cargo test -p pallet-zk-verifier
```

## Notes and limitations

- Verification behavior differs between `runtime-benchmarks`/test builds (mock VK) and production (real Groth16).
- Batch disclosure verification is limited to 10 proofs per call.
- `public_signals` for disclosure must be exactly 76 bytes: `commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]`.

## License

Dual-licensed under Apache-2.0 and GPL-3.0-or-later.
