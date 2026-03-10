# pallet-zk-verifier

FRAME pallet for on-chain verification of Groth16 proofs in Orbinum.

## Status

- MVP in active development.
- Production runtime currently verifies Groth16 proofs only.
- PLONK and Halo2 exist as domain enums for forward compatibility, not as active runtime verification paths.

## What this pallet does

- Stores verification keys by `(circuit_id, version)`.
- Tracks active version per circuit.
- Verifies generic proofs through the `verify_proof` extrinsic.
- Exposes `ZkVerifierPort` for pallet-to-pallet verification flows:
  - `verify_transfer_proof`
  - `verify_unshield_proof`
  - `verify_disclosure_proof`
  - `batch_verify_disclosure_proofs`
  - `verify_private_link_proof`
- Tracks per-version verification statistics.

## Circuit IDs

- `1`: transfer
- `2`: unshield
- `3`: shield (reserved)
- `4`: disclosure
- `5`: private_link

## Storage

- `VerificationKeys`: verification key registry by circuit and version.
- `ActiveCircuitVersion`: currently active version per circuit.
- `VerificationStats`: counters per `(circuit, version)`.

## Extrinsics

- `register_verification_key` (root only)
- `set_active_version` (root only)
- `remove_verification_key` (root only)
- `verify_proof` (signed origin)

## Architecture

The pallet keeps a layered structure:

- `src/domain`: entities, value objects, service traits, repository traits.
- `src/application`: use-case orchestration and command/error DTOs.
- `src/infrastructure`: FRAME repositories, primitive adapters, Groth16 implementation.
- `src/presentation`: extrinsic execution and error mapping helpers.

## Dependencies

- `orbinum-zk-verifier`: Groth16 verification primitives.
- `orbinum-zk-core`: shared ZK primitives.
- FRAME: `frame-support`, `frame-system`, `sp-runtime`, `sp-std`.

## Testing

Run pallet tests from `node/`:

```bash
cargo test -p pallet-zk-verifier
```

## Notes and limitations

- Verification behavior in `runtime-benchmarks`/test builds may differ from production cryptographic execution.
- Batch disclosure verification enforces a fixed max batch size to limit runtime resource usage.

## License

Dual-licensed under Apache-2.0 and GPL-3.0-or-later.
