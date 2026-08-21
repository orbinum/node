# `RuntimeVersion` history

Log of every change to `VERSION` (`template/runtime/src/lib.rs`). Any change
to `spec_version` / `transaction_version` must add a row here in the same PR.

## Bump rules

- **`spec_version`**: any consensus-affecting change — execution logic,
  storage, migrations, proof verification. Nodes reject blocks from a runtime
  with a different `spec_version`; forkless upgrades (`system.setCode`)
  require the new value to be greater.
- **`transaction_version`**: only when the SCALE encoding of extrinsics
  changes (dispatch signatures, argument order/types). Invalidates
  offline-signed extrinsics.
- **`impl_version`**: implementation-only changes with no consensus effect
  (equivalent optimizations). Rarely touched.

## Current era (testnet, post genesis reset 2026-07-15)

The genesis reset (`69d1b837`) set `spec_version` back to 1 and
`transaction_version` to 1 for the public testnet launch.

### spec 10 — tx 3 — [Unreleased]

Validator onboarding moves off-chain, and the EVM relay identity becomes the
operator's to choose. Ships **validator-set 0.3.0** and **relayer 0.4.0**.
**`transaction_version` moves 2 → 3** — call indices are deleted and one
dispatch signature changes, so offline-signed extrinsics are invalidated and
wallets must ship alongside the runtime.

**No migration**, on two verified conditions rather than assumptions:

- `PendingValidators` must be empty on testnet before release. A chain with a
  live queue would need one.
- Every `RelayerByAccount` holder must already be in `ApprovedValidators`. The
  new rules do not reach backwards, so a binding created by the old sudo-gated
  call for a non-validator would keep resolving in the fee path forever. This
  testnet runs 5 operator-owned validators, all in the set, so the gap is empty.

A chain where either does not hold needs migrations for them — for the second,
iterate `RelayerByAccount` and `clear_relayer` any holder outside the set.

**Relay guards**

Folded into this same version — spec 10 has not shipped, so these release with
the onboarding change. `transaction_version` is unaffected: no dispatch
signature changes.

- `set_min_relay_fee` is capped by a new `Config::MaxMinRelayFee` (1 ORB, a
  thousand times the default) and rejects above it with `MinRelayFeeTooHigh`.
  Without a ceiling, one mistyped governance call could brick EVM relay until
  the next runtime upgrade — the call that would lower the fee again has to run
  on the runtime the mistake broke.
- `get_active_relayers` caps its result at 256 entries. The method has no
  callers today and registration is gated on the validator set, so nothing can
  reach the cap; it is headroom for whoever wires it up later.
- New `Event::RelayFeeDiverted`, emitted when relay calldata names an
  unregistered EVM address and the fee falls back to the block author. The
  fallback itself is unchanged — relaying is not gated on registration, so
  rejecting there would fail a user's transaction over someone else's
  misconfiguration. This does not close fee substitution by a *registered*
  relayer: `relayer` is not a public input to the proof, so an approved
  validator with a registered address resolves normally and records no
  diversion. Closing that needs the recipient bound into the circuit.

**Removed — validator self-registration**

- **`register_validator`, `approve_validator`, `reject_validator`** (call
  indices 2, 4, 5 — retired, never to be reassigned), the `PendingValidators`
  storage item, `MaxPendingValidators`, three events and four errors.
  Candidate selection now happens off-chain and sudo records the decision with
  `add_validator`. An on-chain queue only sudo could drain was a slower route
  to the same outcome.
- **`ValidatorPrerequisites::has_relayer`**, which severs the last
  validator-set → relayer coupling.

**Changed**

- **Session-key gate moved to `add_validator`.** Previously it guarded
  `register_validator`. Without it an approved account holding no keys would
  occupy a slot in the active set without ever authoring, leaving gaps in the
  slot schedule.
- **`relayer.register_relayer(who, evm_address)` →
  `register_relayer(evm_address, signature)`**, and from `ManageOrigin` to
  `Signed`. The operator registers their own address; the signer is the owner, so
  nobody can bind an address on another's behalf. **This is the dispatch
  signature change that forces the `transaction_version` bump.**

  `ManageOrigin` previously did two jobs: it kept arbitrary accounts out, and it
  let governance verify the operator actually owned the address. The validator-set
  gate replaces the first. The second needed the `signature`: a relay address is
  public (it is the `caller` of every relay transaction), so without proof of key
  ownership any approved validator could register a rival's address, take its
  fees, and lock the owner out permanently through `AlreadyRegistered`.

- **Zero and precompile-range addresses (`0x0..=0xffff`) are rejected.** Those
  "callers" originate inside the runtime, so no key can sign for them.

- **`SessionManager::new_session` filters out approved accounts with no session
  keys.** `session.purge_keys` is permissionless, so a validator could clear the
  `add_validator` gate and then drop its keys, holding an Aura slot while
  producing nothing.

**Added**

- **`ValidatorSetInterface`** in `pallet-validator-set`, implemented directly on
  its `Pallet<T>`, replacing a hand-written runtime adapter over
  `ApprovedValidators`. Follows the same provider-trait convention as
  `RelayerInterface`.
- **`OnValidatorRemoved` hook**, wired to `pallet_relayer::clear_relayer`: a
  relay binding cannot outlive the validator membership that authorised it.
  Infallible by design — leaving the set must never be blocked by cleanup.
  Accrued `PendingRelayerFees` are untouched; clearing a binding is not
  confiscation.

**Node-side (breaks running validators)**

- The node no longer derives its EVM relay key from the Aura mnemonic. It reads
  keystore type `evmr` instead, so consensus identity no longer dictates EVM
  identity. `relayer_register.rs` is deleted. **Without an `evmr` key a node
  still authors blocks — only relaying stops.** Operators keep their registered
  address by recovering the old key with `scripts/vk/derive-legacy-evm-key.cjs`.
- The relay fee fallback to the block author is **unchanged**: an unregistered
  relayer still credits the block author rather than failing the transaction.

**Removed — dead code**

- **`MigrateToV3` and the `migrations` module.** `Migrations` is now empty —
  every live chain is past v3, so the entry was a no-op behind a
  storage-version guard, and a migration that can no longer run is dead weight
  that could be re-armed by mistake. Replaying it against a v3 state aborts
  with *"produced an already-expired root"*, which `try-runtime
  on-runtime-upgrade` does by design (it forces migrations past their guard),
  so every upgrade rehearsal failed for the wrong reason. **No on-chain effect
  either way** — the guard already made it a single storage read.

### spec 9 — tx 2 — 2026-08-13

Security fixes plus one consensus fix. **`transaction_version` stays at 2** —
no dispatch signature changes, so offline-signed extrinsics remain valid and
wallet and runtime do NOT have to ship together.

**No migration, no storage change.**

**Consensus**

- **The sealed-node sweep no longer sizes its batch from the block's leftover
  weight — this halted the public testnet at block 406997.**
  `pallet-shielded-pool`'s `on_idle` divided `remaining` by the benchmarked
  per-node cost to pick how many nodes to prune. Leftover weight is not
  consensus: once post-dispatch refunds are in play an author and an importer
  measure the same block slightly differently, so each pruned a different
  number of nodes and wrote a different state. Frontier folds that state into
  the Ethereum block header it builds in `on_finalize`, so the divergence
  surfaced as a mismatched `"fron"` digest and `Executive::final_checks`
  panicked with *"Digest item must match that calculated."*

  Three validators with identical state at 406997 and byte-identical extrinsics
  in 406998 produced three mutually unimportable blocks; the chain stopped for 4
  hours. It survived five days on spec 8 only because empty blocks leave the
  same leftover weight on every node — the first block carrying real EVM
  traffic split the network three ways.

  The sweep now runs in `on_initialize` over a constant batch
  (`PRUNED_NODES_PER_BLOCK`, unchanged at 512, ~6.5 ms of a 2 s block) and
  charges the full batch rather than the removals, since a miss costs the same
  read as a hit. The state transition differs only in that it is now identical
  on every node.

  A governance runtime upgrade cannot deliver this fix: applying one needs a
  block, and a forked network no longer agrees on any. Roll the binary out to
  every validator together.

**Security**

- **shielded-pool 0.17.1 — pool admission tags one entry per nullifier**, in a
  namespace shared with `unshield` (`ShieldedPoolSpend`). `and_provides`
  contributes exactly ONE tag, so passing it a `Vec` encoded the whole
  nullifier set plus the relayer into a single blob. Three consequences, each
  free for an attacker since the fee is only charged on execution: reordering
  the two inputs minted a second admissible entry for the same spend; two
  transfers sharing only ONE note (A+B and A+C) did not collide at all, so one
  note could back unboundedly many entries; and transfer/unshield used
  different prefixes, so the same note could back one of each at once. Every
  variant propagates and is revalidated network-wide while at most one can
  execute.

  `relayer` deliberately leaves the tag. Binding it made a copy with a swapped
  fee recipient a *separate* entry, so anyone could rebroadcast another user's
  spend pointed at their own account; keyed on the nullifier the two are
  mutually exclusive, so taking the fee requires out-bidding — which means
  paying it.

  **Admission policy, not state transition** — consensus is unaffected. Nodes
  on the old logic keep accepting the duplicate variants, so the mitigation
  only completes as the network updates.
- **relay — the selector whitelist was stale for BOTH operations (ME-8).** The
  client held `0x47fc44a2` (unshield) and `0x8c0f5d24` (privateTransfer), while
  the decoder answers to `0x4e505348` and `0x66ed2cd4`. Derived by keccak, the
  stale pair turn out to be real selectors from signatures two versions old.
  Relaying was therefore rejecting every call as *"unsupported selector"* —
  silently, because that is indistinguishable from a legitimate rejection. The
  same stale literals sat in the runtime's fallback list and in
  `ts-tests/test-relay-rpc.ts`, so the tests stayed green while testing nothing.

  Both now derive from `pallet_evm_precompile_shielded_pool::selectors::*` (or
  from the ABI signature, in the TypeScript tests), and a unit test pins the
  client constants against the decoder's.
- **relay — per-operation calldata minimums were both 228 bytes**, the shared
  head up to the fee slot. Past that the layouts diverge: unshield's head is 10
  slots (324 with the selector), privateTransfer's is 8 (260). A call between
  228 and its real minimum passed validation and reached the decoder truncated.
- **relay — `gas_price` and the fee word saturate instead of panicking.**
  `U256::as_u128()` panics above 2^128. The fee word is caller-controlled over
  an unauthenticated RPC, so one crafted 32-byte value took down the handler;
  `gas_price` comes from the runtime and is not attacker-reachable, but a panic
  there still kills the relay RPC. Node-side only, no consensus effect.

### spec 8 — tx 2 — 2026-08-08

Bundles the whole audit-remediation batch plus the config/feature work that
preceded it. `transaction_version` stays at 2 — no call index or dispatch
signature changed; the metadata moves, so `spec_version` does.

**Features / config**

- **validator-set 0.2.0 — registration bond removed** (#121). The 1 000 ORB
  `register_validator` bond is gone: `ValidatorBond` and `Currency` Config
  items, the `ValidatorBondOf` map, both bond events and `InsufficientBond`.
  Governance approval already gated the active set, so the bond only added a
  funding step for hand-onboarded operators. No migration — `ValidatorBondOf`
  was queried on testnet first and found empty (0 entries, empty queue, 3
  validators all sudo-added), so nothing stays reserved.
- **shielded-pool — minimum shield amount removed** (#121). `MinShieldAmount`
  and `AmountTooSmall` are gone; any non-zero amount is shieldable, zero still
  refused via `InvalidAmount`. This shifts the numeric index of every `Error`
  variant declared after `AmountTooSmall` — clients matching on error *names*
  are unaffected; anything decoding by index needs fresh metadata.
- **shielded-pool — sealed-tree pruning** (#122). New Config
  `SealedTreePrunedBelowLevel` (production 10) and an `on_idle` sweep that
  reclaims ~99.8% of a sealed tree's `MerkleNodes` (1,048,574 → 2,046 per
  tree); `get_merkle_path` recomputes pruned siblings from `MerkleLeaves` on
  demand. Benchmarked at 12.68 µs/node, so the 512-node per-block ceiling
  costs ~6.5 ms. No migration — nothing prunes until a tree seals at 2^20
  leaves, and the sweep reaches already-sealed trees on its own.
- **runtime config split into modules** (#121). `template/runtime/src/configs/`.
  No consensus effect on its own.
- **legacy `shieldedPool_*` RPC server retired** (#119). Node-side only.

**Security (audit remediation)**

- **zk-verifier — deserialization bounds + circuit-id de-aliasing** (#123).
  `MAX_VK_BYTES` / `MAX_PROOF_BYTES` cap the length prefix before
  `Vec::with_capacity`; circuit ids no longer alias to the same `u8`, and
  genesis asserts VK arity.
- **shielded-pool — zero-hash ladder and tree-depth shift bounded** (#124).
  `zero_hash_at_level` is iterative (a recursive call could exhaust the 1 MB
  Wasm stack and abort the process); a const assertion pins tree `DEPTH < 32`
  so `capacity()` cannot shift into a `u32`.
- **shielded-pool 0.16.0 — non-canonical and zero commitments/nullifiers
  refused** (#125). Both are raw-byte storage keys while byte→field reduces
  mod the BN254 `p`, so `n` and `n + p` were two keys for one element — a
  double-spend vector. `is_canonical` is now checked on every write path
  (`shield`, `private_transfer`, `unshield`); zero commitments refused
  separately since zero is canonical but indistinguishable from an empty tree
  slot. Shifts `Error` indices (breaking for index-decoders, not name-matchers).
- **precompile 0.5.0 — ABI decoder truncation/overflow fixed** (#126).
  Offsets/lengths were narrowed with `low_u32()`; a wrapping length built an
  inverted slice range and panicked the runtime (`wasm unreachable`, reachable
  from an unsigned gas-free `eth_call`). Words are now rejected when they don't
  fit their type, and all offset/length arithmetic is checked. No ABI change.
- **shielded-pool 0.17.0 — duplicate nullifier in `private_transfer` refused**
  (#127). Two equal non-dummy nullifiers spent one input twice (both cleared
  the used-set check, the second `mark_as_used` was idempotent). `execute` now
  rejects a duplicate with `NullifierAlreadyUsed`. Defense in depth.

| spec | tx | Date | Commit | Change |
|------|----|------|--------|--------|
| 7 | 2 | 2026-08-05 | — | Two pallet changes shipping in one upgrade. **shielded-pool 0.14.0:** historic-root window re-anchored from insert counts to block numbers. New Config `RootRetentionBlocks` (300 blocks); `MaxHistoricRoots` (raised to 16384) becomes a queue-length cap rather than the window. `HistoricPoseidonRoots` now stores an expiry block instead of a bool; `HistoricRootsOrder` replaced by the slot-indexed `HistoricRootsQueue` + `Head`/`Tail`. `STORAGE_VERSION` 2 → 3 with `MigrateToV3` in the tuple. Weights re-benchmarked against the v3 layout. The amount-overflow pool rejection moves from `Custom(2)` to `Custom(4)`, which had two meanings. **Applied migrations removed (`72ff7b88`):** the v1/v2 modules are gone from shielded-pool and zk-verifier 0.11.0 — testnet was already past both, so they were no-ops, and `MigrateToV1` rebuilt the whole Merkle tree in one block. `spec_version` moves because storage layout and `on_runtime_upgrade` both change; `transaction_version` stays — no call signature changed. |
| 6 | 2 | 2026-08-03 | — | `pallet-account-mapping` and its precompile (index 14, address 0x0800) removed, along with the `private_link` circuit (id 5) and its verification key. Index 14 is retired and must not be reassigned. zk-verifier 0.10.0 gains `purge_circuit` (call index 7, Root) plus `STORAGE_VERSION` 1 and `MigrateToV1`, which drops the stranded circuit-5 key that no extrinsic could reach. `transaction_version` moves because the new call index changes extrinsic encoding. |
| 5 | 1 | 2026-07-30 | — | shielded-pool 0.12.0: multi-tree forest. Full trees seal (`TreeSealed`, permanent `SealedTreeRoots` anchors) and inserts roll over to a fresh tree — the 2^20-note network ceiling is gone. New Config `MaxLeavesPerTree` (2^20), `STORAGE_VERSION` 2 (`MigrateToV2`, version-only), runtime API v2 (`get_forest_info`, `get_root_for_leaf`). No circuit/extrinsic/ABI changes. |
| 4 | 1 | 2026-07-30 | `63caafca` | shielded-pool 0.11.0: `MerkleNodes` storage (internal nodes written on every insert) + `MigrateToV1` migration (backfill, `STORAGE_VERSION` 1). O(depth) Merkle proofs. Weights re-benchmarked. The upgrade block runs the one-shot migration (~3s at ~90k leaves). |
| 3 | 1 | 2026-07-27 | `d9d40244` | Build with the metadata hash `CheckMetadataHash` requires. |
| 2 | 1 | 2026-07-26 | `c285ac3f` | shielded-pool 0.10.1: `recipient_to_field` reduces mod BN254 r — fixes rejection of most Substrate recipients in `unshield` (consensus halt). |
| 1 | 1 | 2026-07-15 | `69d1b837` | Testnet genesis. Version reset (came from spec 6 in the dev era). |

## Previous era (dev, pre-reset)

History prior to the reset — does not correspond to any live chain.

| spec | tx | Date | Commit | Change |
|------|----|------|--------|--------|
| 6 | 2 | 2026-07-10 | `28decfe4` | `circuit_version` carried in the memo (`MAX_ENCRYPTED_MEMO_SIZE` 176→180). |
| 5 | 2 | 2026-07-09 | `aafb5989` | Per-note circuit versioning with version retirement; `private_transfer`/`unshield`/`claim_shielded_fees` gain a `circuit_version` arg (tx 1→2). |
| 3 | 1 | 2026-07-06 | `2ffd2fce` | Shielded pool hardening. |
| 2 | 1 | 2026-07-04 | `8930d626` | zk-verifier hardening. |
| 1 | 1 | — | `ce10bb01` | Initial Substrate template. |
