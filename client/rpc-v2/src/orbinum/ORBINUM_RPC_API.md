# Orbinum Privacy RPC API

## Overview

The Orbinum RPC module exposes read-only JSON-RPC methods to query privacy-related state from the shielded pool. These endpoints do not modify chain state.

## Namespace

Method names use the `privacy_` prefix.

## Methods

### 1) `privacy_getMerkleRoot`

- **Params:** none
- **Returns:** `string`
  - Current Merkle root as a hex string (typically `0x`-prefixed).

### 2) `privacy_getMerkleProof`

- **Params:**
  - `leaf_index` (`u32`): zero-based index of the commitment leaf.
- **Returns:** object (`MerkleProofResponse`)
  - `path`: `string[]` (sibling hashes in hex)
  - `leaf_index`: `u32`
  - `tree_depth`: `u32`

### 3) `privacy_getNullifierStatus`

- **Params:**
  - `nullifier` (`string`): nullifier hash in hex (with or without `0x` prefix).
- **Returns:** object (`NullifierStatusResponse`)
  - `nullifier`: `string`
  - `is_spent`: `bool`

### 4) `privacy_getPoolStats`

- **Params:** none
- **Returns:** object (`PoolStatsResponse`)
  - `merkle_root`: `string`
  - `commitment_count`: `u32`
  - `total_balance`: `u128` (minimum units)
  - `tree_depth`: `u32`

## Usage Notes

- All methods are query-only and intended for wallets, indexers, and clients.
- Hex values are returned as strings.
- `leaf_index` is expected to be within current tree size.