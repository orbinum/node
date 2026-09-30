# pallet-shielded-pool

FRAME pallet for privacy-preserving transactions in Orbinum using ZK-SNARKs.

## Status

MVP in active development. Core shield / transfer / unshield flows are functional, including partial unshield with automatic change note handling. Relay fees are attributed by relay commit and claimed publicly (no proof).

## What this pallet does

Implements a UTXO-style shielded pool where:

- Public tokens enter via `shield` — converted to on-chain commitments.
- Value moves privately via `private_transfer` — only nullifiers and new commitments appear on-chain.
- Tokens exit via `unshield` — revealed when the user chooses. Supports partial withdrawal: if `change_commitment != [0u8;32]`, the remaining value is wrapped into a new **stealth-addressed note** (unique ephemeral keypair) and re-inserted into the Merkle tree. Change note encrypted memo is stored for wallet recovery.

A Poseidon Merkle tree tracks all commitments. A nullifier set prevents double-spending. All state transitions require a valid Groth16 proof verified by `pallet-zk-verifier`.

### Stealth Addresses for Change Notes

Partial unshield creates change notes that are **unlinkable** — each change note uses an ephemeral keypair derived from the sender's viewing secret key and shared secret:

- **Ephemeral keypair**: generated randomly during `unshield` proof construction
- **Shared secret**: derived via ECDH between ephemeral secret and recipient's viewing public key
- **Stealth owner key**: recipient's owner public key tweaked additively via HKDF(shared_secret)
- **Encrypted memo**: stored on-chain via `CommitmentMemos` for recovery during wallet rescan

This ensures change note commitments are **not linkable** to other notes belonging to the same user.

## Extrinsics

| Extrinsic | Origin | Description |
|-----------|--------|-------------|
| `shield` | Signed | Deposit tokens; insert one commitment into the Merkle tree |
| `shield_batch` | Signed | Deposit and insert multiple commitments in one call |
| `private_transfer` | Unsigned / Signed / Relayed | ZK-proven private transfer between notes. Fee goes to the committed relayer, else the block author |
| `unshield` | Unsigned / Signed / Relayed | ZK-proven withdrawal to a public account. Accepts a `change_commitment` and a 180-byte `change_encrypted_memo` for partial unshield with stealth change notes (empty for a total unshield) |
| `commit_relay` | Signed / Relayed (registered relayer) | Record relay commits for spends about to be submitted |
| `claim_relay_fees` | Signed / Relayed | Pay the caller's pending relay fees out of the pool to its EVM mirror (no proof) |
| `register_asset` | Signed | Register a new asset for multi-asset support |
| `verify_asset` | Root | Mark a registered asset as verified (enables shielding) |
| `unverify_asset` | Root | Remove verified status from an asset |

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
| `Assets` | Registered asset metadata |
| `NextAssetId` | Auto-increment for asset IDs |
| `PoolBalancePerAsset` | Total shielded balance per asset |

## Module layout

```
src/
  lib.rs               — Config, Storage, Events, Errors, extrinsics, origin helpers
  types/               — Commitment, Nullifier, Hash, EncryptedMemo and aliases
  merkle/              — Poseidon Merkle forest (pure tree logic + MerkleTreeService)
  operations/
    mod.rs             — module declarations, `ensure_valid_proof`
    shield.rs          — shield / shield_batch
    private_transfer.rs — TransferRequest + PrivateTransferOperation
    unshield.rs        — UnshieldRequest + UnshieldOperation (partial and total)
    statement.rs       — pool values → verifier statement (memo digest, recipient bytes)
    fees.rs            — relay op hashes, fee attribution by commit, public claim
    assets.rs          — register / verify / unverify asset
  storage/             — one Repository per storage domain
  validate_unsigned/   — mempool anti-spam checks
  helpers.rs           — thin `Pallet<T>` delegations
  genesis.rs           — GenesisConfig and BuildGenesisConfig impl
  runtime_api_impl.rs  — Runtime API implementations (Merkle proofs, tree info)
  tests/               — extrinsic and operation tests, one file per concern
  benchmarking.rs      — FRAME benchmarks
  weights.rs           — WeightInfo trait and generated weights
```

## Security properties

- **Double-spend prevention**: nullifiers are recorded on first use and rejected thereafter.
- **Merkle root validation**: only the current root and historic roots within `MaxHistoricRoots` are accepted.
- **ZK proof verification**: all state-changing extrinsics require a Groth16 proof validated by `pallet-zk-verifier`.
- **Recipient binding**: the recipient's raw 32 bytes go to the verifier, which binds them as `blake2_256(recipient) mod r` under a memo-bound (v2) key, so no other account shares the input. A v1 key binds `recipient mod r`, which `R ± r` aliases.
- **Memo binding**: under a v2 key the proof binds `blake2_256(SCALE(memos)) mod r`, so a copy with other memos fails verification.
- **Change commitment uniqueness**: the pallet rejects a `change_commitment` that already exists in the Merkle tree before inserting it.
- **Change note unlinkability**: each partial unshield creates a stealth-addressed change note with:
  - Unique ephemeral keypair (random per unshield)
  - Stealth owner public key derived via ECDH + HKDF tweak (not linkable to sender's global owner key)
  - Encrypted memo stored in `CommitmentMemos` for off-chain recovery (sent to recipient's viewing public key)
- **Memo encryption**: 176-byte encrypted memos (nonce 12 + ciphertext+MAC 132 + ephPk_packed 32) using ChaCha20-Poly1305 IETF
- **Value range**: memos support u128 values (up to ~340 billion tokens with 18 decimals per note)

These are design properties of the current MVP. No formal security audit has been performed.

## Dependencies

- `pallet-zk-verifier`: proof verification via `ZkVerifierPort`.
- `pallet-relayer`: relay fee accounting via `RelayerInterface`.
- `orbinum-zk-core`: Poseidon hash, commitment and nullifier types.
- FRAME: `frame-support`, `frame-system`, `sp-runtime`.

## Testing

```bash
cargo test -p pallet-shielded-pool
```

## License

Dual-licensed under Apache-2.0 and GPL-3.0-or-later.
