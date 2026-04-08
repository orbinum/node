# Orbinum Privacy RPC API

## Overview

The Orbinum RPC module exposes read-only JSON-RPC methods to query privacy-related state from the shielded pool. These endpoints do not modify chain state.

## Namespace

Method names use the `privacy_` prefix.

## Methods

### 1) `privacy_getMerkleRoot`

- **Params:** none
- **Returns:** `string`
  - Current Merkle root as a `0x`-prefixed 32-byte little-endian hex string.

### 2) `privacy_getMerkleProof`

- **Params:**
  - `leaf_index` (`u32`): zero-based index of the commitment leaf.
- **Returns:** object (`MerkleProofResponse`)
  - `root`: `string` — Merkle root read from the **same block** as the proof (0x-prefixed LE hex).
  - `path`: `string[]` — sibling hashes in 0x-prefixed LE hex, from leaf level to root.
  - `leaf_index`: `u32`
  - `tree_depth`: `u32`

> **Atomicity:** `root` and `path` are always read under the same `best_block` reference,
> eliminating any race condition between a separate `getMerkleRoot` call.

### 3) `privacy_getMerkleProofByCommitment`

- **Params:**
  - `commitment` (`string`): commitment hash as a `0x`-prefixed 32-byte hex string.
- **Returns:** object (`MerkleProofResponse`)
  - `root`: `string` — Merkle root read from the **same block** as the proof (0x-prefixed LE hex).
  - `path`: `string[]` — sibling hashes in 0x-prefixed LE hex, from leaf level to root.
  - `leaf_index`: `u32`
  - `tree_depth`: `u32`

> **Atomicity:** same guarantee as `privacy_getMerkleProof` — root and path share one block snapshot.

### 4) `privacy_getNullifierStatus`

- **Params:**
  - `nullifier` (`string`): nullifier hash in hex (with or without `0x` prefix).
- **Returns:** object (`NullifierStatusResponse`)
  - `nullifier`: `string`
  - `is_spent`: `bool`

### 5) `privacy_getPoolStats`

- **Params:** none
- **Returns:** object (`PoolStatsResponse`)
  - `merkle_root`: `string`
  - `commitment_count`: `u32`
  - `total_balance`: `u128` (minimum units)
  - `asset_balances`: `Array<{ asset_id: u32, balance: u128 }>` (non-zero balances only)
  - `tree_depth`: `u32`

## MerkleProofResponse shape

```json
{
  "root": "0x1a2b3c...",
  "path": ["0xaabb...", "0xccdd...", "..."],
  "leaf_index": 0,
  "tree_depth": 20
}
```

All hex strings are **0x-prefixed 32-byte values encoded in little-endian byte order**,
matching the internal Poseidon hash representation used by the shielded-pool pallet.

## Usage Notes

- All methods are query-only and intended for wallets, indexers, and clients.
- Hex values are returned as strings.
- `leaf_index` is expected to be within current tree size.
- Clients should prefer `privacy_getMerkleProofByCommitment` over calling
  `privacy_getMerkleRoot` + `privacy_getMerkleProof` separately, since the combined
  endpoint guarantees root/path consistency within a single block.