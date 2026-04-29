# pallet-shielded-pool

FRAME pallet for privacy-preserving transactions in Orbinum using ZK-SNARKs.

## Status

MVP in active development. Core shield / transfer / unshield flows are functional. Audit and disclosure features are present but under active review.

## What this pallet does

Implements a UTXO-style shielded pool where:

- Public tokens enter via `shield` — converted to on-chain commitments.
- Value moves privately via `private_transfer` — only nullifiers and new commitments appear on-chain.
- Tokens exit via `unshield` — revealed when the user chooses.

A Poseidon Merkle tree tracks all commitments. A nullifier set prevents double-spending. All state transitions require a valid Groth16 proof verified by `pallet-zk-verifier`.

## Extrinsics

| Extrinsic | Origin | Description |
|-----------|--------|-------------|
| `shield` | Signed | Deposit tokens; insert one commitment into the Merkle tree |
| `shield_batch` | Signed | Deposit and insert multiple commitments in one call |
| `private_transfer` | Signed | ZK-proven private transfer between notes |
| `unshield` | Signed | ZK-proven withdrawal to a public account |
| `disclose` | Signed | Selective disclosure of a note to an auditor |
| `register_asset` | Signed | Register a new asset for multi-asset support |

## Storage

| Item | Description |
|------|-------------|
| `PoseidonRoot` | Current Merkle root |
| `MerkleTreeSize` | Number of inserted commitments |
| `MerkleLeaves` | Commitments indexed by position |
| `NullifierSet` | Spent nullifiers with block number |
| `HistoricPoseidonRoots` | Past roots (accepted for proofs) |
| `HistoricRootsOrder` | Bounded ordered list of historic roots |
| `CommitmentMemos` | Encrypted memos per commitment |
| `AuditPolicies` | Per-account audit policies |
| `DisclosureRequests` | Pending disclosure requests by `(target, auditor)` |
| `DisclosureRecords` | Completed disclosures by `(who, commitment)` |
| `AuditTrailStorage` | Full audit trail entries |
| `NextAuditTrailId` | Auto-increment for audit trail entries |
| `Assets` | Registered asset metadata |
| `NextAssetId` | Auto-increment for asset IDs |
| `PoolBalancePerAsset` | Total shielded balance per asset |
| `LastDisclosureTimestamp` | Rate-limiting per `(who, auditor)` |
| `DisclosureCounters` | Disclosure count per `(who, auditor)` |

## Module layout

```
src/
  lib.rs               — Config, Storage, Events, Errors, extrinsics
  types.rs             — Commitment, Nullifier, Hash, EncryptedMemo and aliases
  merkle.rs            — Poseidon Merkle tree insertion and root update
  operations.rs        — Proof verification dispatch and business logic helpers
  storage.rs           — Storage helper functions (nullifier checks, root lookups)
  helpers.rs           — Miscellaneous internal helpers
  genesis.rs           — GenesisConfig and BuildGenesisConfig impl
  validate_unsigned.rs — ValidateUnsigned impl for unsigned extrinsics
  benchmarking.rs      — FRAME benchmarks
  weights.rs           — WeightInfo trait and generated weights
```

The previous Clean Architecture layers (`domain/`, `application/`, `infrastructure/`, `presentation/`, `tests/`) have been removed. All logic lives in `lib.rs` and the focused modules above.

## Security properties

- Double-spend prevention: nullifiers are recorded on first use and rejected thereafter.
- Merkle root validation: only the current root and historic roots within `MaxHistoricRoots` are accepted.
- ZK proof verification: all state-changing extrinsics require a Groth16 proof validated by `pallet-zk-verifier`.

These are design properties of the current MVP. No formal security audit has been performed.

## Dependencies

- `pallet-zk-verifier`: proof verification via `ZkVerifierPort`.
- `orbinum-zk-core`: Poseidon hash, commitment and nullifier types.
- `orbinum-encrypted-memo`: encrypted memo types.
- FRAME: `frame-support`, `frame-system`, `sp-runtime`.

## Testing

```bash
cargo test -p pallet-shielded-pool
```

## License

Dual-licensed under Apache-2.0 and GPL-3.0-or-later.
