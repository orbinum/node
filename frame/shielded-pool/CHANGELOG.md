# Changelog

All notable changes to `pallet-shielded-pool` will be documented in this file.

## [0.10.0] - 2026-07-10

### Changed
- **`MAX_ENCRYPTED_MEMO_SIZE` 176 → 180** to accommodate the new `circuit_version` field carried in the memo plaintext (see `orbinum-encrypted-memo` 0.7.0). `EncryptedMemo` wire offsets updated: `ciphertext [12..132]`, `tag [132..148]`, `ephPk [148..180]`. The pallet still treats the memo as opaque bytes — only the length bound and slice offsets change.
- **Weights regenerated** (`src/weights.rs`) — the larger memo raises `CommitmentMemos`' `MaxEncodedLen` (`max_size` 226 → 230), changing the `proof_size` of every extrinsic that reads/writes it (`shield`, `shield_batch`, `private_transfer`, `unshield`, `claim_shielded_fees`). Benchmarked on the reference host (`ubuntu-32gb-fsn1-1`, AMD EPYC-Genoa) with `--steps=50 --repeat=20 --chain=dev`. Runtime `spec_version` 5 → 6.

### Breaking
- `EncryptedMemo` now requires exactly 180 bytes; 176-byte memos are rejected. Consensus-affecting (covered by the `spec_version` bump). `transaction_version` is intentionally **not** bumped: the extrinsic SCALE codec is unchanged (the memo arg is still `BoundedVec<u8>` — only its max bound rose), so offline-signed extrinsics still decode identically.

## [0.9.0] - 2026-07-09

### Changed

- **Weights regenerated** on the benchmark host for the `circuit_version`-carrying
  `private_transfer` / `unshield` / `claim_shielded_fees` and the rest of the pallet.

- **`private_transfer`, `unshield` and `claim_shielded_fees` now take a required
  `circuit_version: u32`** (last param). The proof is verified against that
  circuit version's VK instead of always the active version, so a note created
  under an older circuit stays spendable after a VK rotation. The three operation
  functions pass `Some(circuit_version)` to the verifier (no more hardcoded
  `None`). **Consensus-affecting**: the dispatch signatures change → runtime
  `spec_version` 3→4 and `transaction_version` 1→2. The EVM precompile calldata
  gains a trailing `uint32 circuitVersion` (new selectors — see the precompile
  changelog).
- **`validate_unsigned` rejects an unsupported circuit version early**
  (`InvalidTransaction::Custom(10)`) via the new `ZkVerifier::is_supported_version`
  port method, so the tx-pool is not flooded with proofs for versions that have
  no registered VK.

### Security

- `private_transfer` now rejects an unregistered or unverified asset before any
  effect (`InvalidAssetId` / `AssetNotVerified`), matching `shield` and
  `unshield`. It was the only path that skipped the asset state-machine, so
  value already shielded under a frozen asset could still be moved and split
  in-pool; the emergency freeze (`unverify_asset`) now covers every path.
- `private_transfer` weight is now parameterized by the number of outputs. It
  inserts up to two Merkle leaves (a 2-in/2-out transfer) but was charged a flat
  weight benchmarked for a single leaf, under-pricing the second insert (~20
  extra Poseidon hashes plus storage) and letting an attacker fill blocks past
  the metered limit. The benchmark now sweeps `n` outputs and the extrinsic
  charges `private_transfer(commitments.len())`. (Weights carry an interim
  upper-bound placeholder for the extra leaf; regenerate on the benchmark VPS.)
- `shield_batch` now uses its benchmarked `shield_batch(n)` weight and rejects an
  empty batch with `EmptyBatch`. It previously used an ad-hoc `shield() * n * 0.8`
  weight with no fixed base term, which evaluated to zero for an empty batch —
  a free-to-submit signed spam vector — and mispriced small batches versus the
  measured curve.
- Hardened the historic Merkle-root window. `integrity_test` now asserts
  `MaxHistoricRoots > 0` (a zero window would let the known-root map grow
  unbounded while accepting every root forever). Root insertion is now atomic —
  the order vector is pushed before the map is marked, so the two can never
  desync — and eviction keeps a root known while any duplicate copy remains in
  the window.
- Asset registration now rejects an id collision with `AssetIdAlreadyExists`
  instead of silently overwriting an existing asset, guarding against a genesis
  re-init resetting the id counter over live slots. Genesis native-asset
  metadata now uses `expect` instead of `unwrap_or_default`, so an over-long
  name/symbol fails the build loudly rather than launching with an empty string.
- `Note.asset_id` is now `u32` (was `u64`), matching the on-chain registry and
  the circuit's public signal (4-byte LE). The wider field serialized an
  incompatible commitment preimage; the type is test-only today, but the mismatch
  was a latent fund-loss footgun for any wallet building notes from it.
- Hardened the pool-balance ledger invariant (`PoolBalancePerAsset == physical
  pool balance` for the native asset). The accounting was already correct; added
  a `try_state` hook (feature `try-runtime`) that enforces it every block, a
  `defensive_assert!` before the `saturating_sub` in `PoolBalanceRepository`, and
  tests anchoring the invariant across the full fee lifecycle (shield → unshield
  with fee → claim → unshield the fee note) and each operation. No behavioral
  change to the ledger — verification and defense-in-depth only.
- Bound the unsigned `relayer` field into the transaction-pool `provides` tag for
  `unshield` and `private_transfer`. `ValidateUnsigned` now forwards `relayer` to
  validation (it was previously dropped), so a variant differing only in the fee
  recipient is a distinct pool entry and cannot silently replace the honest tx.
  The relayer registry is governance-gated, so an unregistered address cannot
  credit itself — it falls back to the block author (griefing at worst, never
  theft). User funds are never at risk; only fee attribution is affected.
- `claim_shielded_fees` now takes `BoundedVec` for `proof` (max 512) and
  `public_signals` (max 128) instead of unbounded `Vec<u8>`, so oversized inputs
  are rejected by the codec bound before dispatch, matching the other extrinsics.
- The Merkle-tree capacity guard now derives its limit from the fixed
  `MAX_TREE_DEPTH` constant instead of the `MaxTreeDepth` config, so the
  `MerkleTreeFull` check always fires at the real 2^20 capacity even if the config
  is misset. An `integrity_test` asserts `MaxTreeDepth == MAX_TREE_DEPTH` at
  runtime construction, keeping the depth reported to wallets consistent with the
  tree the pallet actually implements.
- `unshield` now rejects a recipient whose encoding is not exactly 32 bytes with
  `InvalidRecipient`, instead of silently binding a zeroed recipient into the
  proof. Production `AccountId` is `AccountId32` (32 bytes) — and every signature
  scheme Orbinum unifies (sr25519/ed25519/ECDSA/EVM, plus future ones like Solana)
  maps to a 32-byte account — so the strict binding covers them all. The test mock
  was migrated from `u64` to `AccountId32` so the binding is exercised end-to-end.
- A non-zero relay fee that cannot be attributed to any recipient (no resolved
  relayer and no block author) now errors with `FeeRecipientUnavailable` instead
  of silently skipping accumulation and stranding the fee tokens in the pool. This
  is unreachable under normal operation (a transaction always executes inside a
  block, so a block author exists) but fails loudly on a misconfigured provider.
- Unsigned `unshield`/`private_transfer` transactions now carry a bounded pool
  longevity (64 blocks) instead of `TransactionLongevity::MAX`, so a transaction
  that is never included does not linger in the pool indefinitely.

### Fixed

- Corrected the `unverify_asset` doc-comment: it claimed existing notes could
  still be spent, but unverifying an asset freezes both shields and unshields
  (an intentional emergency kill-switch for a compromised asset). Behavior
  unchanged; documentation now matches.

## [0.8.3] - 2026-07-04

### Security

- Proof verification for `shield`/`unshield`/`private_transfer`/fee paths is no
  longer bypassed by `runtime-benchmarks`. The bypass now lives behind a dedicated
  `skip-proof-verification` feature that `runtime-benchmarks` does NOT enable, so a
  release runtime exposing benchmarks still verifies proofs. An `integrity_test`
  panics at runtime construction if the bypass feature is compiled into a live
  runtime. Mirrors the same change in `pallet-zk-verifier`.

### Changed

- Regenerated FRAME benchmark weights on reference hardware.

## [0.8.2] - 2026-06-01

### Changed

- Updated FRAME benchmark weights measured on Hetzner CCX33 (AMD EPYC-Milan, 8 vCPU dedicated, 32 GB RAM). Steps: `50`, Repeat: `20`. Covers: `shield`, `shield_batch`, `private_transfer`, `unshield`, `register_asset`, `verify_asset`, `unverify_asset`, `claim_shielded_fees`.

## [0.8.1] - 2026-05-22

### Added

- `benchmarking.rs`: added a new `#[benchmark] fn claim_shielded_fees()` benchmark. This is the first real measured weight (~690 µs on a CCX33). The previous placeholder was 70 µs, underestimating the actual execution time by nearly 10×.
- `operations/fees.rs`: added a `#[cfg(not(feature = "runtime-benchmarks"))]` guard around the `verify_value_proof` call to prevent `CircuitNotFound` during benchmarking, following the same pattern used for `verify_proof` in `pallet-zk-verifier`.

### Changed

- Updated FRAME benchmark weights measured on Hetzner CCX33 (AMD EPYC-Milan, 8 vCPU dedicated, 32 GB RAM). Steps: `50`, Repeat: `20`. Covers: `shield`, `shield_batch`, `private_transfer`, `unshield`, `register_asset`, `verify_asset`, `unverify_asset`, `claim_shielded_fees`.

### Fixed

- `benchmarking.rs`: `private_transfer` and `unshield` benchmarks now use `T::Relayer::min_relay_fee().saturated_into()` as fee instead of `0`, which caused `FeeTooLow` errors and prevented weight generation for those extrinsics.

## [0.8.0] - 2026-05-14

### Added
- **`claim_shielded_fees` extrinsic** — validators claim accrued relay fees as a private shielded note.
  Requires a Groth16 `value_proof` (CircuitId 6) proving that the supplied commitment encodes exactly
  `(amount, asset_id, owner_pubkey, blinding)` via Poseidon4. Prevents fee inflation attacks where a
  relayer could craft a commitment encoding a larger value and later drain the pool via `unshield`.
  Public signals layout (76 bytes): `commitment(32) | value(8) | asset_id(4) | owner_hash(32)`.
- **`claim_relay_fees_to_evm` extrinsic** — signed extrinsic that transfers accrued relay fees to the
  relayer's registered H160 EVM address.
- **`verify_asset` / `unverify_asset` extrinsics** (Root origin) — mark or unmark a registered asset as
  verified, enabling or disabling shielding for that asset.
- **`operations/` module structure** — business logic split into dedicated sub-modules:
  `shield.rs`, `private_transfer.rs`, `unshield.rs`, `fees.rs`, `assets.rs`.
- **`runtime_api_impl.rs`** — Runtime API implementations (Merkle proofs, tree info) extracted from `lib.rs`.
- **`pallet-relayer` integration** — relay fee accounting via `RelayerInterface` trait
  (`accumulate_relay_fee`, `consume_relay_fee`).
- **`verify_value_proof` mock** in `mock.rs` for unit testing `claim_shielded_fees` without on-chain VK.
- **`claim_shielded_fees` weight** added to `WeightInfo` trait and both substrate/rocks implementations.

### Removed
- **Selective disclosure subsystem** — all disclosure extrinsics, storage, and types removed:
  - Extrinsics: `set_audit_policy`, `request_disclosure`, `disclose`, `reject_disclosure`,
    `batch_submit_disclosure_proofs`, `prune_expired_request`, `revoke_disclosure_record`.
  - Storage: `AuditPolicies`, `DisclosureRequests`, `DisclosureRecords`, `AuditTrailStorage`,
    `NextAuditTrailId`, `LastDisclosureTimestamp`, `DisclosureCounters`.
  - Types: `AuditTrail`, `DisclosureRecord`, `DisclosureRequest`, `Auditor`, `DisclosureCondition`.
  - Weight entries: all disclosure-related benchmark weights removed.
  - `operations/disclosure/` module directory entirely removed.

### Changed
- **README**: updated extrinsic table — `disclose` row replaced by `claim_shielded_fees` and
  `claim_relay_fees_to_evm`; removed disclosure storage rows; updated status note.
- **README**: `operations.rs` monolith replaced by `operations/` module directory listing.
- **`helpers.rs`**: storage imports cleaned up — `DisclosureRecords`, `DisclosureRequests` and
  other disclosure-related storage removed from `mock.rs` and helpers.
- **`benchmarking.rs`**: disclosure benchmarks removed; `claim_shielded_fees` benchmark retained.

## [0.7.0] - 2026-05-08

### Added
- **Stealth Address Support for Change Notes** - Enables unlinkable change note commitments during partial unshield
  - New parameter in `unshield` extrinsic: `change_encrypted_memo: &[u8]`
  - New storage map: `CommitmentMemos<T>` - stores encrypted memos keyed by commitment hash
  - Change notes now use ephemeral keypairs for recipient derivation
  - Stealth owner public key derivation via ECDH + HKDF-based tweak

- **Extended Encrypted Memo Support** - Increased from 168 to 176 bytes total
  - Plaintext memo structure: value_lo(8) || value_hi(8) || owner_pk(32) || blinding(32) || asset_id(4) || counterparty_pk(32) = 116 bytes
  - Encrypted memo structure: nonce(12) || ciphertext+MAC(132) || ephPk_packed(32) = 176 bytes
  - Supports u128 values (up to ~340 billion tokens per note with 18 decimals)
  - All memo size validations updated throughout codebase

### Changed
- **Unshield Event Enhanced** - Added change note tracking fields
  - New fields: `change_commitment: Commitment`, `change_encrypted_memo: Vec<u8>`, `change_leaf_index: u32`
  - Allows chain consumers (indexers, wallets) to track change note insertions
  - Change leaf index enables efficient Merkle path retrieval for change note spending

- **Extrinsic Signature** - `unshield` now accepts change_encrypted_memo parameter
  - From: `unshield(proof, merkle_root, nullifier, asset_id, amount, recipient, fee, change_commitment)`
  - To: `unshield(proof, merkle_root, nullifier, asset_id, amount, recipient, fee, change_commitment, change_encrypted_memo)`
  - Change_encrypted_memo can be empty (0 bytes) for full balance unshield with no change

- **Storage Updates** - New storage item for memo persistence
  - `CommitmentMemos<T>` - BTreeMap<Commitment, Vec<u8>>
  - Stores change note encrypted memos for later retrieval during rescan
  - Enables wallet privacy recovery without modifying blockchain state

- **Merkle Tree Integration** - Change notes automatically inserted into tree
  - Change commitment inserted via `insert()` when present
  - Change leaf index tracked and emitted in event
  - Merkle tree size incremented accordingly
  - Historical roots updated to support change note proof verification

### Technical Details

**Crypto Stack Unchanged**:
- Poseidon hashing (commitment = Poseidon4(value_lo, value_hi, owner_pk, blinding))
- ChaCha20-Poly1305 IETF encryption (96-bit nonce, 16-byte AEAD MAC)
- Baby JubJub curve operations for stealth derivation

**Stealth Change Note Flow**:
```
1. During unshield with partial balance:
   - Generate ephemeral keypair: ephSk = random()
   - Derive shared secret: ECDH(ephSk, recipient_ivk_point)
   - Compute stealth owner pk: recipient_pk + HKDF(shared_secret, ...)
   - Create change commitment with stealth pk
   - Encrypt memo with ephSk for later recovery

2. During rescan:
   - Try ECDH with recipient's viewing secret key
   - Derive stealth owner pk and verify it matches note commitment
   - Decrypt memo to recover change note details (value, blinding)
   - Compute spending key for note spending
```

**Backward Compatibility**:
- ❌ BREAKING: Unshield extrinsic signature changed (9 vs 8 parameters)
- ❌ BREAKING: Encrypted memo size validation now 176 bytes (was 168)
- ❌ BREAKING: Event `Unshielded` has new fields (requires event handler updates)
- ✅ Compatible: Private transfer remains unchanged (still 168/176 byte memos)
- ✅ Compatible: Shield extrinsic unchanged (memo size auto-detected)

**Test Coverage**:
- 326/326 integration tests passing
- Comprehensive Merkle tree operations validated
- Nullifier double-spend prevention verified
- Multi-asset support confirmed
- Pool balance tracking tested
- Change note storage and retrieval validated
- Stealth address derivation tested (via integration tests)

### Bug Fixes
- Fixed encrypted memo size validation to enforce 176-byte requirement
- Fixed u128 value truncation in memos (now uses two u64 LE words)
- Fixed CommitmentMemos storage key consistency

## [0.6.1] - 2026-04-15

### Minor Fixes
- Improved error messages for memo size validation
- Optimized nullifier set lookups
- Updated documentation for asset registration

## [0.6.0] - 2026-03-01

### Initial Shielded Pool Release
- Multi-asset support with asset registry
- Merkle tree (binary, depth-configurable) for commitments
- Nullifier tracking to prevent double-spending
- Private transfer with 2-in/2-out UTXO structure
- Partial unshield with change note support (non-stealth)
- ZK proof verification via pallet-zk-verifier
- Runtime API for Merkle tree queries
- Full unit test coverage
