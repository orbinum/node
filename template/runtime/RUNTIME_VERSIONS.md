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
