# Changelog

All notable changes to `pallet-shielded-pool` will be documented in this file.

## [0.15.0] - 2026-08-06

### Added
- New Config constant **`SealedTreePrunedBelowLevel`** (production 10) and an
  `on_idle` hook that reclaims internal Merkle nodes from **sealed** trees.

  A sealed tree kept ~1,048,574 `MerkleNodes` entries forever — roughly 72 MiB
  each, growing without bound across up to 4096 trees, and every full node had to
  retain all of it. That storage serves exactly one purpose: handing Merkle paths
  to wallets so they can build a spend proof. No dispatchable reads it, so
  dropping it cannot affect whether a note is spendable.

  Nodes concentrate at the bottom of the tree: level 1 holds half of them, level
  10 holds 0.1%. Cutting at level 10 therefore frees **99.8%** (1,048,574 → 2,046
  per tree) while a path costs 2^10 leaf reads and 1,023 Poseidon hashes —
  measured at 58.1 µs/hash, so ~60 ms native and ~180 ms in Wasm. Level 12 would
  free only 0.15% more for four times the work.

  The level is configurable rather than fixed because the recompute cost tracks
  validator hardware. `integrity_test` rejects a cut outside `1..tree_depth`.

### Changed
- `get_merkle_path` rebuilds pruned siblings from `MerkleLeaves` on demand. Only
  the sibling subtree is recomputed, never the whole tree, and a **sealed** tree
  is immutable so the result is byte-identical to what was stored. The active
  tree is untouched: still 20 point reads and zero hashes.

### Fixed
- **`zero_hash_at_level` is iterative.** It was defined recursively, one stack
  frame per level, and `get_zero_hash_cached` falls through to it for any level
  past its 21-entry table. `usize` is 32 bits under Wasm, so a caller passing a
  large level would exhaust the runtime's fixed 1 MB stack — and a stack
  overflow there aborts the process rather than raising a catchable panic.

  Measured on a 1 MiB thread: a recursion of this shape returns at 10,000 frames
  and aborts at 20,000. The loop returns at 5,000 with the same stack and would
  at any depth, since it uses a constant number of frames.

  Unreachable today, and not just by configuration: every `level` at every call
  site comes from a `0..depth` loop bound by `DEFAULT_TREE_DEPTH`, so no external
  input selects one. Latent because the ladder is `pub` and the bound lives in
  the callers rather than in the function.

  The digests are unchanged, which is the part that matters: these hashes stand
  in for empty subtrees inside every Merkle path the chain has served, so a
  divergence at any level would invalidate proofs against notes already on
  chain. A test compares the loop against a local recursive reference across
  levels 0-24, including past the cache boundary.

- **`IncrementalMerkleTree` rejects depths of 32 or more at compile time.**
  `capacity()` computes `1u32 << DEPTH`, which is undefined past 31: debug
  builds panic, release builds wrap to 1 and the tree reports itself full after
  a single leaf. The struct is `pub` and generic over depth, so the bound
  belonged on the type rather than only in the runtime's `integrity_test`. A
  const assertion now fails the build instead.

- `hash_pair_poseidon` clamps its output copy instead of slicing `&bytes[..32]`
  raw. BN254 `Fr` always yields 32 bytes, so the clamp never binds today — but
  this runs on the block-import path, where slicing past the end panics the node
  rather than failing a call. `recipient_to_field` was already written this way;
  the two now match.

### Removed
- **Minimum shield amount.** The `MinShieldAmount` Config constant (1 ORB in the
  runtime) and the `AmountTooSmall` error are gone. `shield` now accepts any
  non-zero amount.

  The floor kept small deposits out of the pool without buying much: it does not
  bound storage, since one leaf costs the same at 1 planck as at 1 ORB, and the
  transaction fee already prices the write. What it did do is force a user with
  a fractional balance to leave it unshielded.

  Zero is still rejected, now via the existing `InvalidAmount` — a zero-value
  note occupies a leaf and a memo slot while carrying nothing.

  **Breaking:** `AmountTooSmall` no longer exists, which shifts the numeric index
  of every `Error` variant declared after it. Clients that match on the error
  *name* (the usual case) are unaffected; anything decoding by index must be
  rebuilt against the new metadata.

### Notes
- Nothing is pruned until a tree seals, which takes 2^20 leaves. No live chain
  has reached that, so no migration is needed — the sweep reaches already-sealed
  trees on its own.
- The sweep is bounded twice: by the block's leftover weight and by
  `MAX_PRUNED_NODES_PER_BLOCK` (512), which caps trie churn on an idle chain. It
  charges every probe rather than only removals, so a level that is already clean
  cannot scan for free. Progress is parked in `SealedPruneCursor`.
- **`on_idle` is benchmarked**, at 12.68 µs per node plus a 0.25 µs base. The
  512-node ceiling therefore costs ~6.5 ms, about 0.3% of a 2s block, and a full
  sealed tree (1,046,528 prunable nodes) drains in ~2,044 blocks — around 3.4
  hours at 6s. The placeholder it replaces charged nothing for execution and
  leaned entirely on `DbWeight`, so it over-declared the per-node cost by ~10x:
  the sweep would have run, just far below the batch size the block could afford.

### Verification
308 pallet tests (11 new) and 65 precompile tests; runtime, `try-runtime` and
`runtime-benchmarks` all compile. The decisive unit test captures the Merkle path
of every leaf in a sealed tree, prunes, and asserts byte-for-byte equality — a
single diverging hash would invalidate every proof against that tree. A dev-node
E2E (`ts-tests/sealed-tree-pruning.test.cjs`, 14/14) covers the config wiring, that
the active tree keeps every level, and that the sweep stays idle while nothing has
sealed. It cannot seal a tree itself: `MaxLeavesPerTree` is a compile-time
constant, so sealing on-chain would need 2^20 shields.

A second dev-node E2E (`ts-tests/no-bond-no-min-shield.test.cjs`, 11/11) covers the
removed minimum: `MinShieldAmount` and `AmountTooSmall` are absent from metadata, a
1-planck shield lands in the pool balance, and zero is still refused with
`InvalidAmount`.

## [0.14.0] - 2026-08-05

### Changed
- **Historic-root window is now measured in blocks, not in inserts.** The window
  was bounded by `MaxHistoricRoots` (100) counted in *leaf insertions*, while an
  unsigned transaction stays valid in the pool for `TX_LONGEVITY` (64) *blocks*.
  A `private_transfer` inserts up to 2 commitments, so ~50 transfers rotated the
  whole window: under load an honest spend passed `validate_unsigned`, gossiped
  across the network, and only then reverted with `UnknownMerkleRoot`, with its
  nullifier still unspent. No attacker was required — ordinary throughput did it,
  and an attacker could force it cheaply with valid transfers.
- New Config constant **`RootRetentionBlocks`** (production 300 blocks, ~30 min at
  6s) sets the window. `integrity_test` asserts it exceeds `TX_LONGEVITY`, so a
  runtime that misaligns the two units refuses to build.
- **`MaxHistoricRoots` changed meaning**: it is no longer the window but a safety
  cap on queue length (production 16384, sized for ~54 sustained inserts/block).
  Reaching it logs a warning rather than silently shortening the window.
- `HistoricPoseidonRoots` value type `bool` → `BlockNumberFor<T>` (the block at
  which a root stops being accepted), `OptionQuery`.
- `HistoricRootsOrder` (a single `BoundedVec`) replaced by a slot-indexed queue:
  `HistoricRootsQueue: StorageMap<u64, (Hash, expiry)>` plus `HistoricRootsHead`
  and `HistoricRootsTail`. A `StorageValue` would be read and rewritten in full on
  every leaf insert — hundreds of KiB on the hottest path once the window holds
  thousands of roots. The map touches one entry plus the few it prunes.
- Pruning is lazy and capped at `MAX_ROOTS_PRUNED_PER_INSERT` (4) per insert, so
  one extrinsic never pays for a backlog it did not create. Leftovers drain on
  subsequent inserts; a stale queue slot is harmless because spendability is
  decided by the expiry stored per root, never by queue membership.
- **Weights re-benchmarked against the v3 layout.** The recorded storage access
  now covers `HistoricRootsQueue` / `HistoricRootsHead` / `HistoricRootsTail` and
  drops the `HistoricRootsOrder` entry, which no longer exists. The measurement
  exercises a queue with expired entries, so the per-insert pruning is charged
  rather than free: `shield` 17r/34w, `unshield` 16r/8w, and per-`n` components
  on `shield_batch` (2r/6w) and `private_transfer` (3r/6w).
- **Pool-rejection code for `amount + fee` overflow moved from `Custom(2)` to
  `Custom(4)`.** Code 2 previously meant two different things depending on which
  validator rejected the transaction — "all inputs are dummy" in
  `private_transfer`, "amount overflow" in `unshield` — so a `Custom error: 2` in
  a node log was ambiguous. The other codes keep their values. Codes are part of
  the observable interface, so a test now pins them.
- `is_known_root` now accepts the **active root unconditionally**. Expiries are
  only refreshed by a leaf insert and the pallet has no hooks, so on a chain idle
  for a full window the current root — the one every wallet proves against —
  would expire and wedge the pool: `private_transfer` and `unshield` both need a
  known root, and only a funded `shield` could mint a new one.

### Added
- `migrations::v3::MigrateToV3` (`STORAGE_VERSION` 2 → 3). Both value types
  changed, so v2 entries cannot be decoded by the new definitions and are
  rewritten here. Every existing root is kept and granted a full window from the
  upgrade block rather than dropped: a root on chain backs proofs wallets may be
  about to submit. The old map is enumerated by **raw key** rather than
  `translate`, which does not delete an entry whose value fails to decode — it
  logs, skips, and leaves the bytes in place, which for a 1-byte `bool` under a
  4-byte slot would leave an unreadable, unprunable residue. Map and queue are
  written in the same loop so the two can never diverge.

### Fixed
- Honest spends no longer revert with `UnknownMerkleRoot` after passing pool
  admission: a root now outlives every transaction admitted against it.
- Map and queue can no longer diverge, which previously left roots reachable by
  neither the pruner nor an eviction path — permanently spendable and impossible
  to remove.
- The cap path no longer drops a root whose window has not elapsed; a live root
  is re-queued instead of being forgotten.
- Reaching the queue cap logs a warning instead of using `defensive!`, which
  expands to `debug_assert!(false)` and would halt a validator running a
  debug-assertions build on a reachable operational state.

### Refactored
- The four largest modules were split into directories, one file per
  responsibility. No behaviour change: every type and function keeps its path
  through re-exports, so no caller outside the pallet was touched.
  - `merkle.rs` (1642 lines) → `merkle/` — `hashing`, `tree`, `batch`, `service`.
    The split isolates the only storage-touching layer (`service`) from the pure
    maths; `batch` now states in its own docs that it is O(n) and used off-chain
    only, which the single file left implicit.
  - `storage.rs` (658 lines) → `storage/` — one module per repository: `asset`,
    `commitment`, `merkle`, `nullifier`, `stats`, `balance`.
  - `validate_unsigned.rs` (683 lines) → `validate_unsigned/` — `transfer`,
    `unshield`, and a new `codes` module holding the named rejection codes that
    were previously bare literals duplicated across both validators.
  - `types.rs` (719 lines) → `types/` — `ids`, `note`, `merkle`, `memo`, `asset`.

### Verification
298 pallet tests, 65 precompile tests, and 78 end-to-end checks against a running
dev node covering `shield_batch`, same-block bursts, idle chains, the steady-state
plateau (299 → 301 slots after +30 inserts), orphan detection in both directions,
and a spend against a root the chain has churned past.

### Notes
- `spec_version` moves 6 → 7 in this release: the storage layout changes and a
  migration is back in the tuple. `transaction_version` stays — no call
  signature changed.

## [0.13.0] - 2026-08-04

### Removed
- **`migrations` module.** Every live chain is at storage version v2 (verified
  on-chain against testnet at block 283941), and a fresh chain starts there via
  genesis, so `MigrateToV1`/`MigrateToV2` were no-ops guarded by their version
  checks. Keeping `MigrateToV1` was a liability rather than a safety net: it
  rebuilds the entire Merkle tree inside a single `on_runtime_upgrade`, which
  cannot be split across blocks. At the testnet's 134201 leaves that is already
  a ~4 MB `Vec` and ~270k writes in one block; at the 2^20 tree cap it would
  exhaust the Wasm heap and produce a block no validator can import. Storage
  version history stays documented on `STORAGE_VERSION`; see git history if an
  old chain ever needs the code. The runtime's `Migrations` tuple is now empty.
  `try-runtime` features are unaffected — they back `try_state`, not migrations.
  `STORAGE_VERSION` itself is unchanged (still v2) — this removes the upgrade
  path, not the on-chain layout.

## [0.12.0] - 2026-07-30

### Added
- **Multi-tree forest: the 2^20-note network ceiling is gone.** When a tree
  reaches `MaxLeavesPerTree` the filling insert seals it and inserts continue
  in a fresh tree. The global u32 leaf index never resets
  (`tree_id = leaf_index / MaxLeavesPerTree`), so event shapes, indexer
  chunking and wallet scan cursors are untouched. Zero circuit, VK,
  extrinsic-signature or precompile-ABI changes — anchoring stays root-only.
- New storage `SealedTreeRoots` / `SealedRootIndex`: a sealed tree's final
  root is a **permanent** anchor (bounded by tree count, max 4096 — never
  evicted, unlike the historic ring), so notes in sealed trees stay spendable
  forever. `MerkleRepository::is_known_root` = historic ring OR sealed set;
  transfer/unshield/validate_unsigned call sites unchanged. Regression test:
  a sealed root survives `MaxHistoricRoots + N` later inserts.
- New Config `MaxLeavesPerTree` (production 2^20; `integrity_test` enforces
  power-of-two ≤ 2^`MAX_TREE_DEPTH` — clients derive `tree_id` from this
  constant, so it must never change on a live chain). Mocks use 8 to make
  rollover testable.
- New event `TreeSealed { tree_id, final_root, first_leaf_index, leaf_count }`,
  emitted after the `MerkleRootUpdated` that carries the final root.
- Runtime API v2 (`api_version(2)`): `get_forest_info()` and
  `get_root_for_leaf(leaf_index)` — sealed trees resolve to their permanent
  root, the active tree to the live `PoseidonRoot`.
- `STORAGE_VERSION` 2 with version-only `migrations::v2::MigrateToV2`
  (sealed maps start empty). Forest invariants merged into the existing
  `try_state` hook: active root always known, one sealed root per completed
  tree, sealed maps bijective.

### Changed
- `Error::MerkleTreeFull` now means the absolute forest ceiling (u32
  leaf-index space, ~4096 trees) — practically unreachable — instead of the
  per-tree 2^20 cap.
- `insert_leaf` / `get_merkle_path` index `MerkleNodes` by tree-local
  position (`leaf_index % MaxLeavesPerTree`). Identical to the previous
  global indexing for tree 0, so v1-backfilled data needs no migration.
- Consensus-affecting (seal writes new storage on the filling insert):
  requires a runtime `spec_version` bump at release. `transaction_version`
  unchanged.

### Fixed
- Privacy RPC (`fc-rpc-v2`): proof endpoints no longer fall back to the
  active root when a leaf's anchoring root cannot be resolved — that would
  have served a sealed-tree path with the wrong anchor; they now return an
  explicit error. Both endpoints gain a `tree_id` response field (additive).

### Verified E2E
- Against a local dev node with an 8-leaf cap: 10 shields cross the first
  seal; `TreeSealed` fires; sealed leaves anchor to the permanent final root
  and active leaves to the live root via `privacy_getMerkleProof*`
  (`ts-tests/test-forest-e2e.ts`).

## [0.11.0] - 2026-07-30

### Added
- **`MerkleNodes` storage: internal tree nodes persisted on insert.** The
  frontier walk in `insert_leaf` already computed every node along the
  insertion path and discarded them; they are now written to
  `MerkleNodes: StorageNMap<(tree_id, level, index), Hash>` (levels 1..=19 —
  level 0 is `MerkleLeaves`, level 20 is `PoseidonRoot`). The key includes
  `tree_id` (fixed at 0 on the current single tree) so the planned multi-tree
  forest needs no storage remapping.
- **`MigrateToV1`** (`src/migrations.rs`): one-shot backfill of `MerkleNodes`
  from existing leaves, idempotent, guarded by the new pallet
  `STORAGE_VERSION(1)`. try-runtime `post_upgrade` verifies the backfilled
  level-19 nodes derive `PoseidonRoot`. Rehearsed against a live testnet
  snapshot (~block 202k): migration weight is ~3s of ref_time at ~90k leaves —
  the upgrade block runs overweight once; re-evaluate (or move to MBM) if
  deployed above ~150k leaves.

### Changed
- **`get_merkle_path` is O(depth): 20 point reads, zero hashing** — it
  previously loaded *every* leaf and rebuilt all 20 levels per call (O(n)
  reads + O(n) Poseidon hashes). Missing siblings resolve to the canonical
  zero hash. `MerkleRepository::get_all_leaves` removed with it.
- **Weights regenerated** on the reference host (`ubuntu-32gb-hel1-1`, AMD
  EPYC-Genoa, `--steps=50 --repeat=20`): every leaf-inserting extrinsic pays
  the node writes (`shield` 13 → 32 writes; batched inserts dedupe shared
  ancestors, e.g. 20-leaf `shield_batch` touches ~35 distinct node keys, not
  19×20). Known pre-existing gap: the `unshield` benchmark exercises the
  no-change-note path.
- Consensus-affecting (new storage writes on every insert): requires a
  runtime `spec_version` bump at release. `transaction_version` unchanged —
  no extrinsic signature changes.

### Related (outside this crate)
- `privacy_getMerkleProof` / `privacy_getMerkleProofByCommitment` (fc-rpc-v2)
  now route through the runtime API: O(1) index lookup via
  `CommitmentToLeafIndex` instead of a linear leaf scan, and the
  `MAX_RPC_LEAVES = 100_000` cap is removed. Response shape unchanged.
- The runtime now implements the `TryRuntime` API, and its `build.rs` skips
  the Poseidon host-function feature on try-runtime builds so the stock
  try-runtime CLI can execute the wasm.

## [0.10.1] - 2026-07-17

### Fixed
- **`unshield` rejected most Substrate recipients with `ProofVerificationFailed`.**
  `recipient_to_field` passed the raw 32 `AccountId32` bytes as the `recipient`
  public input, but provers bind `recipient` reduced mod BN254 r (LE bytes mod r)
  and the verifier rejects non-canonical public inputs — so any recipient whose
  LE value ≥ r (~4 of 5 random AccountId32s) always failed verification. EVM
  recipients were unaffected (H160 + 12 zero bytes is always < r), which masked
  the bug on the precompile path. `recipient_to_field` now reduces mod r,
  matching the prover. **Consensus-affecting** (verification acceptance
  changes): runtime `spec_version` 1 → 2. `transaction_version` unchanged —
  extrinsic SCALE encoding is untouched.

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
