# fc-rpc-v2 — Orbinum Privacy RPC

Read-only JSON-RPC layer for the Orbinum shielded pool. Exposes five endpoints that query `pallet-shielded-pool` storage directly, without going through the Runtime API.

## Crate layout

```
src/
├── lib.rs        — crate root, re-exports public types
└── privacy.rs    — all five endpoints, response types, and tests
```

## Public API

### Server struct

```rust
pub struct PrivacyRpc<C, B, BE> { ... }

impl<C, B, BE> PrivacyRpc<C, B, BE> {
    pub fn new(client: Arc<C>) -> Self
}
```

Bounds required on the generic parameters:

| Parameter | Required traits |
|-----------|----------------|
| `C` | `HeaderBackend<B>` + `ScStorageProvider<B, BE>` + `Send + Sync + 'static` |
| `B` | `BlockT` |
| `BE` | `sc_client_api::Backend<B>` + `Send + Sync + 'static` |

### Registering with the node

```rust
use fc_rpc_v2::{PrivacyApiServer, PrivacyRpc};

io.merge(PrivacyRpc::new(client.clone()).into_rpc())?;
```

---

## Endpoints

### `privacy_getMerkleRoot`

Returns the current Merkle tree root.

**Parameters:** none

**Result:** `String` — `0x`-prefixed 32-byte hex

```json
// request
{ "jsonrpc": "2.0", "method": "privacy_getMerkleRoot", "params": [], "id": 1 }

// response
{ "jsonrpc": "2.0", "result": "0x1a2b3c...", "id": 1 }
```

**Errors**
- `InternalError` — pool not initialized (storage empty)

---

### `privacy_getMerkleProof`

Returns the Merkle sibling-path proof for a given leaf index. The `root` and `path` are read from the same best block (atomic — no mismatch possible).

The path algorithm mirrors `IncrementalMerkleTree::generate_proof` in `pallet-shielded-pool` exactly, so the result can be fed directly into the ZK circuits.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `leaf_index` | `u32` | 0-based index of the commitment leaf |

**Result:** `MerkleProofResponse`

```json
{
  "root":       "0x...",         // Merkle root at best block
  "path":       ["0x...", ...],  // 20 sibling hashes (level 0 → root)
  "leaf_index": 5,
  "tree_depth": 20
}
```

**Errors**
- `InternalError` — pool not initialized or tree is empty
- `InvalidParams` — `leaf_index >= tree_size`

---

### `privacy_getMerkleProofByCommitment`

Returns the Merkle sibling-path proof for the note with the given commitment. Scans `MerkleLeaves` linearly to resolve the leaf index, then delegates to the same path builder as `privacy_getMerkleProof`. The `root` and `path` are read from the same best block (atomic — no mismatch possible).

Used by the SDK when the caller knows the commitment hex but not the leaf index (normal case for wallet operations).

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `commitment` | `String` | `0x`-prefixed hex string, exactly 32 bytes (64 hex chars) |

**Result:** `MerkleProofResponse`

```json
{
  "root":       "0x...",         // Merkle root at best block
  "path":       ["0x...", ...],  // 20 sibling hashes (level 0 → root)
  "leaf_index": 3,
  "tree_depth": 20
}
```

**Errors**
- `InternalError` — pool not initialized or tree is empty
- `InvalidParams` — not valid hex, not exactly 32 bytes, or commitment not found in the tree

---

### `privacy_getNullifierStatus`

Checks whether a nullifier has already been spent.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `nullifier` | `String` | `0x`-prefixed hex string, exactly 32 bytes (64 hex chars) |

**Result:** `NullifierStatusResponse`

```json
{
  "nullifier": "0x...",
  "is_spent":  true
}
```

**Errors**
- `InvalidParams` — not valid hex, or not exactly 32 bytes

---

### `privacy_getPoolStats`

Returns aggregate statistics for the shielded pool.

**Parameters:** none

**Result:** `PoolStatsResponse`

```json
{
  "merkle_root":       "0x...",
  "commitment_count":  42,
  "total_balance":     1000000,
  "asset_balances": [
    { "asset_id": 0, "balance": 700000 },
    { "asset_id": 1, "balance": 300000 }
  ],
  "tree_depth": 20
}
```

**Errors**
- `InternalError` — pool not initialized (`commitment_count == 0`)

---

## Response types

All types implement `Serialize`, `Deserialize`, `Clone`, `Debug`, `PartialEq`, `Eq`.

```rust
pub struct MerkleProofResponse {
    pub root:       String,      // 0x-prefixed hex — Merkle root
    pub path:       Vec<String>, // 20 sibling hashes, level 0 first
    pub leaf_index: u32,
    pub tree_depth: u32,         // always 20
}

pub struct NullifierStatusResponse {
    pub nullifier: String, // 0x-prefixed hex
    pub is_spent:  bool,
}

pub struct AssetBalanceResponse {
    pub asset_id: u32,
    pub balance:  u128,
}

pub struct PoolStatsResponse {
    pub merkle_root:      String,
    pub commitment_count: u32,
    pub total_balance:    u128,
    pub asset_balances:   Vec<AssetBalanceResponse>,
    pub tree_depth:       u32,  // always 20
}
```

---

## Storage access

All endpoints query `pallet-shielded-pool` storage directly using `sc_client_api::StorageProvider`. No Runtime API call is made, which means:

- No runtime upgrade required to add or change these endpoints.
- Keys are built with the standard Substrate hasher layout:

| Storage item | Key layout | Hasher |
|---|---|---|
| `PoseidonRoot` | `Twox128("ShieldedPool") ++ Twox128("PoseidonRoot")` | — |
| `MerkleTreeSize` | `Twox128("ShieldedPool") ++ Twox128("MerkleTreeSize")` | — |
| `MerkleLeaves` | `Twox128("ShieldedPool") ++ Twox128("MerkleLeaves") ++ Blake2_128Concat(u32)` | `Blake2_128Concat` |
| `NullifierSet` | `Twox128("ShieldedPool") ++ Twox128("NullifierSet") ++ Blake2_128Concat(H256)` | `Blake2_128Concat` |
| `NextAssetId` | `Twox128("ShieldedPool") ++ Twox128("NextAssetId")` | — |
| `PoolBalancePerAsset` | `Twox128("ShieldedPool") ++ Twox128("PoolBalancePerAsset") ++ Blake2_128Concat(u32)` | `Blake2_128Concat` |

---

## Tests

37 unit tests in `privacy.rs` covering:

- **`storage_keys`** — byte lengths, pallet prefix, per-item and per-key differentiation
- **`merkle_path`** — `build_merkle_path` against known vectors (1/2/3/4-leaf trees, sibling correctness at each level, progressive zero hashes, odd/even index handling)
- **`response_types`** — JSON field names, round-trip serde for all four response structs
- **`nullifier_validation`** — hex parsing guard: rejects invalid hex, wrong lengths; accepts with/without `0x` prefix
- **`commitment_validation`** — same guards applied to the commitment parameter of `privacy_getMerkleProofByCommitment`

```
cargo test -p fc-rpc-v2
```
