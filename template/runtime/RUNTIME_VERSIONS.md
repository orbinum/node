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

| spec | tx | Date | Commit | Change |
|------|----|------|--------|--------|
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
