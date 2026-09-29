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

Id `6` (the retired `value_proof`) is unknown to the pallet; its keys can be purged.

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

Cross-pallet trait implemented by `Pallet<T>`. `pallet-shielded-pool` describes each spend as a statement of domain values; the pallet encodes it for the key it verifies against:

```rust
pub trait ZkVerifierPort {
    fn verify_transfer_proof(proof: &[u8], statement: &TransferStatement, version: Option<u32>)
        -> Result<bool, DispatchError>;
    fn verify_unshield_proof(proof: &[u8], statement: &UnshieldStatement, version: Option<u32>)
        -> Result<bool, DispatchError>;
    fn is_supported_version(circuit_id: u32, version: u32) -> bool;
}
```

`TransferStatement` / `UnshieldStatement` carry the public values, the recipient's raw 32 bytes and `memo_digest = blake2_256(SCALE(memos))`.

## Module layout

```
src/
  lib.rs          — pallet definition (Config, Storage, Events, Errors, extrinsics)
  port.rs         — ZkVerifierPort, the statements, and the Pallet<T> impl
  encoding.rs     — statement → public inputs, per input layout
  verifier.rs     — version resolution, key preparation, verification, stats
  types.rs        — CircuitId, type aliases
  weights.rs      — WeightInfo trait + generated weights
```

## Dependencies

- `orbinum-zk-verifier`: `Groth16Verifier`, `Proof`, `PublicInputs`, `VerifyingKey`.
- `orbinum-zk-core`: shared field types.
- FRAME: `frame-support`, `frame-system`, `sp-runtime`.

## Testing

```bash
cargo test -p pallet-zk-verifier
```

## Public-input encoding

The key's arity picks the layout (`orbinum_zk_verifier::input_layout`): the circuit's base arity is `Base`, one more is `MemoBound`. Any other arity fails verification. Numbers are little-endian in a 32-byte slot; every input is a canonical BN254 field element.

**Transfer** — `merkle_root | nullifiers.. | commitments.. | asset_id | fee [| memo_hash]`

**Unshield** — `merkle_root | nullifier | amount | recipient | asset_id | fee | change_commitment [| memo_hash]`

| Value | `Base` (v1) | `MemoBound` (v2) |
|-------|-------------|------------------|
| `recipient` | raw bytes mod r | `blake2_256(raw) mod r` |
| `memo_hash` | — | `memo_digest mod r` |

Hashing the recipient closes an aliasing hole of the base layout: `R` and `R ± r` are distinct accounts but the same field element, so a copier could redirect a v1 unshield to an account nobody controls. It stays open for v1 until that version is retired.

## Notes and limitations

- Test builds stub the pairing (`do_verify` returns `true`); keys must still deserialize.
- A new version of an existing circuit id must accept the same notes under rules at least as strict (see `register_verification_key`).

## License

Dual-licensed under Apache-2.0 and GPL-3.0-or-later.
