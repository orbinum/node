//! Privacy RPC — Orbinum shielded pool (4 endpoints, 1 file)
//!
//! Endpoints:
//! - `privacy_getMerkleRoot`       — current Merkle root as hex
//! - `privacy_getMerkleProof`      — sibling path for a leaf index
//! - `privacy_getNullifierStatus`  — whether a nullifier has been spent
//! - `privacy_getPoolStats`        — aggregate pool statistics

use jsonrpsee::{
	core::RpcResult,
	proc_macros::rpc,
	types::error::{ErrorCode, ErrorObject},
};
use pallet_shielded_pool::{
	merkle::{get_zero_hash_cached, hash_pair_poseidon},
	DEFAULT_TREE_DEPTH,
};
use sc_client_api::StorageProvider as ScStorageProvider;
use scale_codec::Decode;
use serde::{Deserialize, Serialize};
use sp_blockchain::HeaderBackend;
use sp_core::{
	hashing::{blake2_128, twox_128},
	storage::StorageKey,
	H256,
};
use sp_runtime::traits::Block as BlockT;
use std::{marker::PhantomData, sync::Arc};

// ============================================================================
// Storage key helpers
// ============================================================================

const PALLET: &[u8] = b"ShieldedPool";
const TREE_DEPTH: usize = 20;

/// Builds `twox_128(pallet) ++ twox_128(item)` (32 bytes — `StorageValue` key).
fn value_key(item: &[u8]) -> Vec<u8> {
	[twox_128(PALLET), twox_128(item)].concat()
}

/// Builds `twox_128(pallet) ++ twox_128(item) ++ blake2_128_concat(map_key)`
/// (standard `StorageMap` key with `Blake2_128Concat` hasher).
fn map_key(item: &[u8], k: &[u8]) -> Vec<u8> {
	let mut key = value_key(item);
	key.extend_from_slice(&blake2_128(k)); // 16-byte hash
	key.extend_from_slice(k); // original key
	key
}

// ============================================================================
// Response types
// ============================================================================

/// Response for `privacy_getMerkleProof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofResponse {
	/// Current Merkle root read from the same block as the proof (`0x`-prefixed hex).
	pub root: String,
	/// Sibling path — 20 `0x`-prefixed hex strings.
	pub path: Vec<String>,
	/// Leaf index used to generate this proof.
	pub leaf_index: u32,
	/// Tree depth (always 20 for circuit compatibility).
	pub tree_depth: u32,
}

/// Response for `privacy_getNullifierStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierStatusResponse {
	/// Nullifier as `0x`-prefixed hex.
	pub nullifier: String,
	/// `true` if the nullifier has been spent.
	pub is_spent: bool,
}

/// Per-asset balance entry for `privacy_getPoolStats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetBalanceResponse {
	pub asset_id: u32,
	pub balance: u128,
}

/// Response for `privacy_getPoolStats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolStatsResponse {
	pub merkle_root: String,
	pub commitment_count: u32,
	pub total_balance: u128,
	pub asset_balances: Vec<AssetBalanceResponse>,
	pub tree_depth: u32,
}

// ============================================================================
// RPC trait
// ============================================================================

#[rpc(server)]
pub trait PrivacyApi {
	/// Returns the current Merkle tree root as a `0x`-prefixed hex string.
	#[method(name = "privacy_getMerkleRoot")]
	fn get_merkle_root(&self) -> RpcResult<String>;

	/// Returns a Merkle sibling-path proof for the leaf at `leaf_index`.
	#[method(name = "privacy_getMerkleProof")]
	fn get_merkle_proof(&self, leaf_index: u32) -> RpcResult<MerkleProofResponse>;

	/// Returns a Merkle sibling-path proof for the given commitment (`0x`-prefixed hex, 32 bytes).
	/// Scans `MerkleLeaves` linearly to resolve the leaf index.
	/// Returns an error if the commitment is not found in the tree.
	#[method(name = "privacy_getMerkleProofByCommitment")]
	fn get_merkle_proof_by_commitment(&self, commitment: String) -> RpcResult<MerkleProofResponse>;

	/// Returns whether the nullifier (`0x`-prefixed hex, 32 bytes) has been spent.
	#[method(name = "privacy_getNullifierStatus")]
	fn get_nullifier_status(&self, nullifier: String) -> RpcResult<NullifierStatusResponse>;

	/// Returns aggregate statistics for the shielded pool.
	#[method(name = "privacy_getPoolStats")]
	fn get_pool_stats(&self) -> RpcResult<PoolStatsResponse>;
}

// ============================================================================
// RPC server
// ============================================================================

/// Privacy RPC server for the Orbinum shielded pool.
pub struct PrivacyRpc<C, B, BE> {
	client: Arc<C>,
	_ph: PhantomData<(B, BE)>,
}

impl<C, B, BE> PrivacyRpc<C, B, BE> {
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			_ph: PhantomData,
		}
	}
}

// ============================================================================
// Error helpers
// ============================================================================

fn internal_error(msg: impl std::fmt::Display) -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InternalError.code(),
		format!("Internal error: {msg}"),
		None::<()>,
	)
}

fn invalid_params(msg: impl std::fmt::Display) -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InvalidParams.code(),
		format!("Invalid params: {msg}"),
		None::<()>,
	)
}

fn pool_not_initialized() -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InternalError.code(),
		"Shielded pool is not initialized",
		None::<()>,
	)
}

// ============================================================================
// Storage helper — shared across all handler methods
// ============================================================================

fn read_storage<B: BlockT, C: ScStorageProvider<B, BE>, BE: sc_client_api::Backend<B>>(
	client: &C,
	hash: B::Hash,
	key: Vec<u8>,
) -> RpcResult<Option<Vec<u8>>> {
	ScStorageProvider::storage(client, hash, &StorageKey(key))
		.map_err(internal_error)
		.map(|opt| opt.map(|data| data.0))
}

// ============================================================================
// Pure Merkle path builder — extracted for testability
//
// Mirrors `IncrementalMerkleTree::generate_proof` in the pallet exactly.
// Returns a `TREE_DEPTH`-element sibling path (raw bytes).
// ============================================================================

fn build_merkle_path(leaves: &[[u8; 32]], leaf_index: usize) -> Vec<[u8; 32]> {
	let mut current_level = leaves.to_vec();
	let mut path = Vec::with_capacity(TREE_DEPTH);
	let mut target = leaf_index;

	for level in 0..TREE_DEPTH {
		// Pad odd levels with the canonical zero hash for this level.
		if current_level.len() % 2 != 0 {
			current_level.push(get_zero_hash_cached(level));
		}

		let sibling_idx = target ^ 1;
		let sibling = if sibling_idx < current_level.len() {
			current_level[sibling_idx]
		} else {
			get_zero_hash_cached(level)
		};
		path.push(sibling);

		// Compute the parent level.
		let mut next: Vec<[u8; 32]> = Vec::with_capacity(current_level.len().div_ceil(2));
		for chunk in current_level.chunks(2) {
			let left = chunk[0];
			let right = chunk
				.get(1)
				.copied()
				.unwrap_or_else(|| get_zero_hash_cached(level));
			next.push(hash_pair_poseidon(&left, &right));
		}
		current_level = next;
		target /= 2;
	}

	path
}

// ============================================================================
// PrivacyApiServer implementation
// ============================================================================

impl<C, B, BE> PrivacyApiServer for PrivacyRpc<C, B, BE>
where
	C: HeaderBackend<B> + ScStorageProvider<B, BE> + Send + Sync + 'static,
	B: BlockT,
	BE: sc_client_api::Backend<B> + Send + Sync + 'static,
{
	fn get_merkle_root(&self) -> RpcResult<String> {
		let best_hash = self.client.info().best_hash;

		let data = read_storage(&*self.client, best_hash, value_key(b"PoseidonRoot"))?
			.ok_or_else(pool_not_initialized)?;

		let root = H256::decode(&mut &data[..]).map_err(internal_error)?;
		Ok(format!("0x{}", hex::encode(root.as_bytes())))
	}

	fn get_merkle_proof(&self, leaf_index: u32) -> RpcResult<MerkleProofResponse> {
		let best_hash = self.client.info().best_hash;

		// Tree size
		let size_data = read_storage(&*self.client, best_hash, value_key(b"MerkleTreeSize"))?
			.ok_or_else(pool_not_initialized)?;
		let tree_size = u32::decode(&mut &size_data[..]).map_err(internal_error)?;

		if tree_size == 0 {
			return Err(pool_not_initialized());
		}
		if leaf_index >= tree_size {
			return Err(invalid_params(format!(
				"leaf_index {leaf_index} >= tree_size {tree_size}"
			)));
		}

		// Load all leaves
		let current_level: Vec<[u8; 32]> = (0..tree_size)
			.map(|i| {
				let data = read_storage(
					&*self.client,
					best_hash,
					map_key(b"MerkleLeaves", &i.to_le_bytes()),
				)?
				.ok_or_else(|| internal_error(format!("leaf {i} missing from storage")))?;
				let h256 = H256::decode(&mut &data[..]).map_err(internal_error)?;
				Ok::<[u8; 32], ErrorObject<'static>>(h256.into())
			})
			.collect::<Result<_, _>>()?;

		// Read root from same block (atomic — no root/path mismatch)
		let root_data = read_storage(&*self.client, best_hash, value_key(b"PoseidonRoot"))?
			.ok_or_else(pool_not_initialized)?;
		let root = H256::decode(&mut &root_data[..]).map_err(internal_error)?;

		// Build sibling path using the shared pure function.
		let raw_path = build_merkle_path(&current_level, leaf_index as usize);
		let path: Vec<String> = raw_path
			.iter()
			.map(|s| format!("0x{}", hex::encode(s)))
			.collect();

		Ok(MerkleProofResponse {
			root: format!("0x{}", hex::encode(root.as_bytes())),
			path,
			leaf_index,
			tree_depth: TREE_DEPTH as u32,
		})
	}

	fn get_merkle_proof_by_commitment(&self, commitment: String) -> RpcResult<MerkleProofResponse> {
		let best_hash = self.client.info().best_hash;

		// Parse commitment hex
		let hex_str = commitment.trim_start_matches("0x");
		let bytes =
			hex::decode(hex_str).map_err(|_| invalid_params("commitment must be valid hex"))?;
		if bytes.len() != 32 {
			return Err(invalid_params(
				"commitment must be exactly 32 bytes (64 hex chars)",
			));
		}
		let target = H256::from_slice(&bytes);

		// Tree size
		let size_data = read_storage(&*self.client, best_hash, value_key(b"MerkleTreeSize"))?
			.ok_or_else(pool_not_initialized)?;
		let tree_size = u32::decode(&mut &size_data[..]).map_err(internal_error)?;

		if tree_size == 0 {
			return Err(pool_not_initialized());
		}

		// Load all leaves; find the matching commitment
		let mut leaf_index: Option<u32> = None;
		let mut current_level: Vec<[u8; 32]> = Vec::with_capacity(tree_size as usize);

		for i in 0..tree_size {
			let data = read_storage(
				&*self.client,
				best_hash,
				map_key(b"MerkleLeaves", &i.to_le_bytes()),
			)?
			.ok_or_else(|| internal_error(format!("leaf {i} missing from storage")))?;
			let h256 = H256::decode(&mut &data[..]).map_err(internal_error)?;
			if leaf_index.is_none() && h256 == target {
				leaf_index = Some(i);
			}
			current_level.push(h256.into());
		}

		let leaf_index = leaf_index.ok_or_else(|| {
			invalid_params(format!(
				"commitment 0x{hex_str} not found in the Merkle tree"
			))
		})?;

		// Read root from same block (atomic — no root/path mismatch)
		let root_data = read_storage(&*self.client, best_hash, value_key(b"PoseidonRoot"))?
			.ok_or_else(pool_not_initialized)?;
		let root = H256::decode(&mut &root_data[..]).map_err(internal_error)?;

		let raw_path = build_merkle_path(&current_level, leaf_index as usize);
		let path: Vec<String> = raw_path
			.iter()
			.map(|s| format!("0x{}", hex::encode(s)))
			.collect();

		Ok(MerkleProofResponse {
			root: format!("0x{}", hex::encode(root.as_bytes())),
			path,
			leaf_index,
			tree_depth: TREE_DEPTH as u32,
		})
	}

	fn get_nullifier_status(&self, nullifier: String) -> RpcResult<NullifierStatusResponse> {
		let best_hash = self.client.info().best_hash;

		let hex_str = nullifier.trim_start_matches("0x");
		let bytes =
			hex::decode(hex_str).map_err(|_| invalid_params("nullifier must be valid hex"))?;
		if bytes.len() != 32 {
			return Err(invalid_params(
				"nullifier must be exactly 32 bytes (64 hex chars)",
			));
		}
		let null_h256 = H256::from_slice(&bytes);

		let data = read_storage(
			&*self.client,
			best_hash,
			map_key(b"NullifierSet", null_h256.as_bytes()),
		)?;

		Ok(NullifierStatusResponse {
			nullifier: format!("0x{}", hex::encode(&bytes)),
			is_spent: data.is_some(),
		})
	}

	fn get_pool_stats(&self) -> RpcResult<PoolStatsResponse> {
		let best_hash = self.client.info().best_hash;

		// Merkle root
		let root_data = read_storage(&*self.client, best_hash, value_key(b"PoseidonRoot"))?
			.ok_or_else(pool_not_initialized)?;
		let root = H256::decode(&mut &root_data[..]).map_err(internal_error)?;

		// Tree size
		let size_data = read_storage(&*self.client, best_hash, value_key(b"MerkleTreeSize"))?
			.ok_or_else(pool_not_initialized)?;
		let commitment_count = u32::decode(&mut &size_data[..]).map_err(internal_error)?;

		if commitment_count == 0 {
			return Err(pool_not_initialized());
		}

		// Next asset ID — drives the per-asset balance scan
		let next_id_data = read_storage(&*self.client, best_hash, value_key(b"NextAssetId"))?
			.ok_or_else(pool_not_initialized)?;
		let next_asset_id = u32::decode(&mut &next_id_data[..]).map_err(internal_error)?;

		// Aggregate per-asset balances
		let mut asset_balances: Vec<AssetBalanceResponse> = Vec::new();
		let mut total_balance: u128 = 0;

		for asset_id in 0..next_asset_id {
			let data = read_storage(
				&*self.client,
				best_hash,
				map_key(b"PoolBalancePerAsset", &asset_id.to_le_bytes()),
			)?;
			if let Some(raw) = data {
				let balance = u128::decode(&mut &raw[..]).map_err(internal_error)?;
				if balance > 0 {
					total_balance = total_balance
						.checked_add(balance)
						.ok_or_else(|| internal_error("pool balance overflow"))?;
					asset_balances.push(AssetBalanceResponse { asset_id, balance });
				}
			}
		}

		Ok(PoolStatsResponse {
			merkle_root: format!("0x{}", hex::encode(root.as_bytes())),
			commitment_count,
			total_balance,
			asset_balances,
			tree_depth: DEFAULT_TREE_DEPTH as u32,
		})
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use pallet_shielded_pool::merkle::{get_zero_hash_cached, hash_pair_poseidon};
	use sp_core::hashing::twox_128;

	// -------------------------------------------------------------------------
	// Storage key helpers
	// -------------------------------------------------------------------------

	mod storage_keys {
		use super::*;

		#[test]
		fn value_key_is_32_bytes() {
			assert_eq!(value_key(b"PoseidonRoot").len(), 32);
			assert_eq!(value_key(b"MerkleTreeSize").len(), 32);
			assert_eq!(value_key(b"NextAssetId").len(), 32);
		}

		#[test]
		fn value_key_is_deterministic() {
			assert_eq!(value_key(b"PoseidonRoot"), value_key(b"PoseidonRoot"));
		}

		#[test]
		fn value_key_starts_with_pallet_prefix() {
			let pallet_prefix = twox_128(b"ShieldedPool");
			let key = value_key(b"PoseidonRoot");
			assert_eq!(&key[..16], &pallet_prefix);
		}

		#[test]
		fn value_key_differs_per_item() {
			assert_ne!(value_key(b"PoseidonRoot"), value_key(b"MerkleTreeSize"));
			assert_ne!(value_key(b"MerkleTreeSize"), value_key(b"NextAssetId"));
		}

		#[test]
		fn map_key_for_u32_is_52_bytes() {
			// 32 prefix + 16 blake2_128 hash + 4 LE bytes
			let key = map_key(b"MerkleLeaves", &0u32.to_le_bytes());
			assert_eq!(key.len(), 52);
		}

		#[test]
		fn map_key_for_h256_is_80_bytes() {
			// 32 prefix + 16 blake2_128 hash + 32 H256 bytes
			let key = map_key(b"NullifierSet", &[0u8; 32]);
			assert_eq!(key.len(), 80);
		}

		#[test]
		fn map_key_shares_prefix_with_value_key_of_same_item() {
			let vk = value_key(b"MerkleLeaves");
			let mk = map_key(b"MerkleLeaves", &0u32.to_le_bytes());
			assert_eq!(&mk[..32], &vk[..]);
		}

		#[test]
		fn map_key_differs_for_different_map_keys() {
			let k0 = map_key(b"MerkleLeaves", &0u32.to_le_bytes());
			let k1 = map_key(b"MerkleLeaves", &1u32.to_le_bytes());
			assert_ne!(k0, k1);
			// Pallet+item prefix must be identical
			assert_eq!(&k0[..32], &k1[..32]);
		}

		#[test]
		fn map_key_encodes_original_bytes_after_hash() {
			let raw = 42u32.to_le_bytes();
			let key = map_key(b"MerkleLeaves", &raw);
			// Last 4 bytes must be the original LE-encoded key
			assert_eq!(&key[key.len() - 4..], &raw);
		}
	}

	// -------------------------------------------------------------------------
	// build_merkle_path algorithm
	// -------------------------------------------------------------------------

	mod merkle_path {
		use super::*;

		fn leaf(byte: u8) -> [u8; 32] {
			let mut arr = [0u8; 32];
			arr[0] = byte;
			arr
		}

		#[test]
		fn path_is_always_tree_depth_elements() {
			for n in [1u32, 2, 3, 5, 10, 20] {
				let leaves: Vec<[u8; 32]> = (0..n).map(|i| leaf(i as u8)).collect();
				let path = build_merkle_path(&leaves, 0);
				assert_eq!(
					path.len(),
					TREE_DEPTH,
					"path len must be {TREE_DEPTH} for n={n}"
				);
			}
		}

		#[test]
		fn single_leaf_sibling_at_level0_is_zero_hash() {
			let path = build_merkle_path(&[leaf(0xAA)], 0);
			assert_eq!(path[0], get_zero_hash_cached(0));
		}

		#[test]
		fn two_leaves_sibling_is_the_other_leaf() {
			let l0 = leaf(0xAA);
			let l1 = leaf(0xBB);
			let path0 = build_merkle_path(&[l0, l1], 0);
			let path1 = build_merkle_path(&[l0, l1], 1);
			assert_eq!(path0[0], l1, "sibling of l0 must be l1");
			assert_eq!(path1[0], l0, "sibling of l1 must be l0");
		}

		#[test]
		fn last_leaf_in_odd_tree_gets_zero_hash_sibling() {
			// Tree of 3: leaf index 2 is paired with a padded zero hash.
			let leaves = vec![leaf(1), leaf(2), leaf(3)];
			let path = build_merkle_path(&leaves, 2);
			assert_eq!(path[0], get_zero_hash_cached(0));
		}

		#[test]
		fn two_leaves_in_same_pair_share_upper_path() {
			let l0 = leaf(0x11);
			let l1 = leaf(0x22);
			let path0 = build_merkle_path(&[l0, l1], 0);
			let path1 = build_merkle_path(&[l0, l1], 1);
			// Both leaves produce the same parent node, so levels 1..DEPTH must match.
			assert_eq!(&path0[1..], &path1[1..]);
		}

		#[test]
		fn level1_sibling_is_hash_of_sibling_pair() {
			let l = [leaf(0x11), leaf(0x22), leaf(0x33), leaf(0x44)];
			let path0 = build_merkle_path(&l, 0);
			// l0 is in pair (l0, l1). The sibling at level 1 is hash(l2, l3).
			assert_eq!(path0[0], l[1]);
			assert_eq!(path0[1], hash_pair_poseidon(&l[2], &l[3]));
		}

		#[test]
		fn leaf_index_1_in_4_leaf_tree_correct_siblings() {
			let l = [leaf(0x11), leaf(0x22), leaf(0x33), leaf(0x44)];
			let path1 = build_merkle_path(&l, 1);
			assert_eq!(path1[0], l[0]);
			assert_eq!(path1[1], hash_pair_poseidon(&l[2], &l[3]));
		}

		#[test]
		fn upper_path_levels_use_progressive_zero_hashes_for_single_leaf() {
			let path = build_merkle_path(&[leaf(0xFF)], 0);
			// After level 0 the single leaf is hashed with zero_hash[0] to form the
			// level-1 node. The sibling at level 1 must be zero_hash[1], and so on.
			for level in 1..TREE_DEPTH {
				assert_eq!(path[level], get_zero_hash_cached(level));
			}
		}
	}

	// -------------------------------------------------------------------------
	// Response type serialization
	// -------------------------------------------------------------------------

	mod response_types {
		use super::*;

		#[test]
		fn merkle_proof_response_json_fields() {
			let resp = MerkleProofResponse {
				root: "0xaabb".to_string(),
				path: vec!["0x1111".to_string(), "0x2222".to_string()],
				leaf_index: 7,
				tree_depth: 20,
			};
			let json = serde_json::to_value(&resp).unwrap();
			assert_eq!(json["root"], "0xaabb");
			assert_eq!(json["leaf_index"], 7);
			assert_eq!(json["tree_depth"], 20);
			assert_eq!(json["path"].as_array().unwrap().len(), 2);
		}

		#[test]
		fn merkle_proof_response_round_trips_serde() {
			let orig = MerkleProofResponse {
				root: "0x00".to_string(),
				path: vec!["0xaa".to_string()],
				leaf_index: 3,
				tree_depth: 20,
			};
			let back: MerkleProofResponse =
				serde_json::from_str(&serde_json::to_string(&orig).unwrap()).unwrap();
			assert_eq!(orig, back);
		}

		#[test]
		fn nullifier_status_response_json_fields() {
			let resp = NullifierStatusResponse {
				nullifier: "0xdeadbeef".to_string(),
				is_spent: true,
			};
			let json = serde_json::to_value(&resp).unwrap();
			assert_eq!(json["nullifier"], "0xdeadbeef");
			assert_eq!(json["is_spent"], true);
		}

		#[test]
		fn nullifier_status_response_round_trips_serde() {
			let orig = NullifierStatusResponse {
				nullifier: "0x1234".to_string(),
				is_spent: false,
			};
			let back: NullifierStatusResponse =
				serde_json::from_str(&serde_json::to_string(&orig).unwrap()).unwrap();
			assert_eq!(orig, back);
		}

		#[test]
		fn pool_stats_response_json_structure() {
			let resp = PoolStatsResponse {
				merkle_root: "0x01".to_string(),
				commitment_count: 5,
				total_balance: 1_000,
				asset_balances: vec![
					AssetBalanceResponse {
						asset_id: 0,
						balance: 600,
					},
					AssetBalanceResponse {
						asset_id: 1,
						balance: 400,
					},
				],
				tree_depth: 20,
			};
			let json = serde_json::to_value(&resp).unwrap();
			assert_eq!(json["commitment_count"], 5u64);
			assert_eq!(json["total_balance"].as_u64().unwrap(), 1_000u64);
			let ab = json["asset_balances"].as_array().unwrap();
			assert_eq!(ab.len(), 2);
			assert_eq!(ab[0]["asset_id"], 0u64);
			assert_eq!(ab[0]["balance"].as_u64().unwrap(), 600u64);
		}

		#[test]
		fn pool_stats_response_round_trips_serde() {
			let orig = PoolStatsResponse {
				merkle_root: "0xff".to_string(),
				commitment_count: 1,
				total_balance: 42,
				asset_balances: vec![AssetBalanceResponse {
					asset_id: 0,
					balance: 42,
				}],
				tree_depth: 20,
			};
			let back: PoolStatsResponse =
				serde_json::from_str(&serde_json::to_string(&orig).unwrap()).unwrap();
			assert_eq!(orig, back);
		}
	}

	// -------------------------------------------------------------------------
	// Nullifier parameter validation (pure parsing logic)
	// -------------------------------------------------------------------------

	mod nullifier_validation {
		use super::*;

		/// Mirrors the hex-parsing guard in `get_nullifier_status`.
		fn parse_nullifier_hex(s: &str) -> Result<H256, ErrorObject<'static>> {
			let hex_str = s.trim_start_matches("0x");
			let bytes =
				hex::decode(hex_str).map_err(|_| invalid_params("nullifier must be valid hex"))?;
			if bytes.len() != 32 {
				return Err(invalid_params(
					"nullifier must be exactly 32 bytes (64 hex chars)",
				));
			}
			Ok(H256::from_slice(&bytes))
		}

		#[test]
		fn rejects_non_hex_input() {
			assert!(parse_nullifier_hex("not-hex").is_err());
			assert!(parse_nullifier_hex("0xnothex").is_err());
		}

		#[test]
		fn rejects_too_short_hex() {
			assert!(parse_nullifier_hex("0x1234").is_err());
			assert!(parse_nullifier_hex(&"ab".repeat(31)).is_err());
		}

		#[test]
		fn rejects_too_long_hex() {
			assert!(parse_nullifier_hex(&format!("0x{}", "ab".repeat(33))).is_err());
		}

		#[test]
		fn accepts_32_byte_hex_with_0x_prefix() {
			assert!(parse_nullifier_hex(&format!("0x{}", "ab".repeat(32))).is_ok());
		}

		#[test]
		fn accepts_32_byte_hex_without_prefix() {
			assert!(parse_nullifier_hex(&"cd".repeat(32)).is_ok());
		}

		#[test]
		fn parsed_bytes_match_input_exactly() {
			let input: Vec<u8> = (0..32).collect();
			let hex_str = format!("0x{}", hex::encode(&input));
			let h256 = parse_nullifier_hex(&hex_str).unwrap();
			assert_eq!(h256.as_bytes(), input.as_slice());
		}

		#[test]
		fn zero_nullifier_is_accepted() {
			let zero = format!("0x{}", "00".repeat(32));
			let h256 = parse_nullifier_hex(&zero).unwrap();
			assert_eq!(h256, H256::zero());
		}
	}

	// -------------------------------------------------------------------------
	// Commitment parameter validation (pure parsing logic)
	// -------------------------------------------------------------------------

	mod commitment_validation {
		use super::*;

		/// Mirrors the hex-parsing guard in `get_merkle_proof_by_commitment`.
		fn parse_commitment_hex(s: &str) -> Result<H256, ErrorObject<'static>> {
			let hex_str = s.trim_start_matches("0x");
			let bytes =
				hex::decode(hex_str).map_err(|_| invalid_params("commitment must be valid hex"))?;
			if bytes.len() != 32 {
				return Err(invalid_params(
					"commitment must be exactly 32 bytes (64 hex chars)",
				));
			}
			Ok(H256::from_slice(&bytes))
		}

		#[test]
		fn rejects_non_hex_input() {
			assert!(parse_commitment_hex("not-hex").is_err());
			assert!(parse_commitment_hex("0xnothex").is_err());
		}

		#[test]
		fn rejects_too_short_hex() {
			assert!(parse_commitment_hex("0x1234").is_err());
			assert!(parse_commitment_hex(&"ab".repeat(31)).is_err());
		}

		#[test]
		fn rejects_too_long_hex() {
			assert!(parse_commitment_hex(&format!("0x{}", "ab".repeat(33))).is_err());
		}

		#[test]
		fn accepts_32_byte_hex_with_0x_prefix() {
			assert!(parse_commitment_hex(&format!("0x{}", "ab".repeat(32))).is_ok());
		}

		#[test]
		fn accepts_32_byte_hex_without_prefix() {
			assert!(parse_commitment_hex(&"cd".repeat(32)).is_ok());
		}

		#[test]
		fn parsed_bytes_match_input_exactly() {
			let input: Vec<u8> = (0..32).collect();
			let hex_str = format!("0x{}", hex::encode(&input));
			let h256 = parse_commitment_hex(&hex_str).unwrap();
			assert_eq!(h256.as_bytes(), input.as_slice());
		}

		#[test]
		fn zero_commitment_is_accepted() {
			let zero = format!("0x{}", "00".repeat(32));
			let h256 = parse_commitment_hex(&zero).unwrap();
			assert_eq!(h256, H256::zero());
		}
	}
}
