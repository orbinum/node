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
| `5` | private_link |
| `6` | value_proof (relay fee claiming) |

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
        recipient: &[u8; 32],   // LE field element — NOT byte-reversed
        asset_id: u32,
        fee: u128,
        change_commitment: &[u8; 32],  // [0u8;32] for total unshield
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

    fn verify_value_proof(
        proof: &[u8],
        public_signals: &[u8],  // exactly 76 bytes: commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]
        version: Option<u32>,
    ) -> Result<bool, DispatchError>;

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

## Public-input encoding

`encoding.rs` converts typed domain parameters to `Vec<[u8; 32]>` LE field elements.

**Unshield** — 7 field elements in order:

| Index | Field | Encoding |
|-------|-------|----------|
| 0 | `merkle_root` | 32 bytes as-is (LE) |
| 1 | `nullifier` | 32 bytes as-is (LE) |
| 2 | `amount` | u128 LE in first 16 bytes of a 32-byte slot |
| 3 | `recipient` | 32 bytes as-is — LE field element (`bytesToBigintLE` convention) |
| 4 | `asset_id` | u32 LE in first 4 bytes of a 32-byte slot |
| 5 | `fee` | u128 LE in first 16 bytes of a 32-byte slot |
| 6 | `change_commitment` | 32 bytes as-is; `[0u8;32]` for total unshield |

The `recipient` is passed **without byte-reversal**. `PublicInputs::to_field_elements` calls `Bn254Fr::from_le_bytes_mod_order`, which matches the TypeScript SDK convention `bytesToBigintLE(accountId32Bytes)`.

## Notes and limitations

- Verification behavior differs between `runtime-benchmarks`/test builds (mock VK) and production (real Groth16).
- `public_signals` for `verify_value_proof` must be exactly 76 bytes: `commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]`.

## License

Dual-licensed under Apache-2.0 and GPL-3.0-or-later.
