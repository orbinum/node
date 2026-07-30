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
use pallet_shielded_pool::DEFAULT_TREE_DEPTH;
use pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi;
use sc_client_api::StorageProvider as ScStorageProvider;
use scale_codec::Decode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp_api::ProvideRuntimeApi;

/// `u128` serde helper: serialises as a decimal string so JavaScript clients
/// can parse values larger than `Number.MAX_SAFE_INTEGER` without precision loss.
mod serde_u128_str {
	use super::*;

	pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&v.to_string())
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
		String::deserialize(d)?
			.parse::<u128>()
			.map_err(serde::de::Error::custom)
	}
}
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
	/// Root the leaf's tree anchors to, read at the same block as the proof
	/// (`0x`-prefixed hex): the permanent sealed root for completed trees,
	/// the live root for the active tree.
	pub root: String,
	/// Sibling path — 20 `0x`-prefixed hex strings.
	pub path: Vec<String>,
	/// Leaf index used to generate this proof.
	pub leaf_index: u32,
	/// Tree depth (always 20 for circuit compatibility).
	pub tree_depth: u32,
	/// Forest tree the leaf belongs to (0 until the first tree seals).
	pub tree_id: u32,
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
	/// Serialised as a decimal string to preserve precision in JS (u128 can exceed
	/// `Number.MAX_SAFE_INTEGER` for large balances with 18 decimals).
	#[serde(with = "serde_u128_str")]
	pub balance: u128,
}

/// Response for `privacy_getPoolStats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolStatsResponse {
	pub merkle_root: String,
	pub commitment_count: u32,
	pub nullifier_count: u64,
	/// Serialised as a decimal string to preserve precision in JS.
	#[serde(with = "serde_u128_str")]
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
	/// Resolves the leaf index via the on-chain reverse index (O(1)) and reads the
	/// stored sibling path (O(depth)). Root and path come from the same block.
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

fn pool_is_empty() -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InternalError.code(),
		"Shielded pool has no commitments",
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
// PrivacyApiServer implementation
// ============================================================================

impl<C, B, BE> PrivacyApiServer for PrivacyRpc<C, B, BE>
where
	C: HeaderBackend<B> + ScStorageProvider<B, BE> + ProvideRuntimeApi<B> + Send + Sync + 'static,
	C::Api: ShieldedPoolRuntimeApi<B>,
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
		// Both runtime-API calls execute at the same block, so root and path
		// can never mismatch.
		let best_hash = self.client.info().best_hash;
		let api = self.client.runtime_api();

		let (_, tree_size, tree_depth) = api
			.get_merkle_tree_info(best_hash)
			.map_err(internal_error)?;

		if tree_size == 0 {
			return Err(pool_is_empty());
		}
		if leaf_index >= tree_size {
			return Err(invalid_params(format!(
				"leaf_index {leaf_index} >= tree_size {tree_size}"
			)));
		}

		let proof = api
			.get_merkle_proof(best_hash, leaf_index)
			.map_err(internal_error)?
			.ok_or_else(|| internal_error(format!("no proof for leaf_index {leaf_index}")))?;

		// Sealed trees anchor to their permanent root, not the active one.
		// A missing entry for an existing leaf means broken sealed-root state;
		// erroring beats silently serving the wrong anchor.
		let (root, tree_id) = api
			.get_root_for_leaf(best_hash, leaf_index)
			.map_err(internal_error)?
			.ok_or_else(|| {
				internal_error(format!("no anchoring root for leaf_index {leaf_index}"))
			})?;

		Ok(MerkleProofResponse {
			root: format!("0x{}", hex::encode(root)),
			path: proof
				.siblings
				.iter()
				.map(|s| format!("0x{}", hex::encode(s)))
				.collect(),
			leaf_index,
			tree_depth,
			tree_id,
		})
	}

	fn get_merkle_proof_by_commitment(&self, commitment: String) -> RpcResult<MerkleProofResponse> {
		let best_hash = self.client.info().best_hash;
		let api = self.client.runtime_api();

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

		let (_, tree_size, tree_depth) = api
			.get_merkle_tree_info(best_hash)
			.map_err(internal_error)?;

		if tree_size == 0 {
			return Err(pool_is_empty());
		}

		let (leaf_index, proof) = api
			.get_merkle_proof_for_commitment(best_hash, target.into())
			.map_err(internal_error)?
			.ok_or_else(|| {
				invalid_params(format!(
					"commitment 0x{hex_str} not found in the Merkle tree"
				))
			})?;

		// Sealed trees anchor to their permanent root, not the active one.
		// A missing entry for an existing leaf means broken sealed-root state;
		// erroring beats silently serving the wrong anchor.
		let (root, tree_id) = api
			.get_root_for_leaf(best_hash, leaf_index)
			.map_err(internal_error)?
			.ok_or_else(|| {
				internal_error(format!("no anchoring root for leaf_index {leaf_index}"))
			})?;

		Ok(MerkleProofResponse {
			root: format!("0x{}", hex::encode(root)),
			path: proof
				.siblings
				.iter()
				.map(|s| format!("0x{}", hex::encode(s)))
				.collect(),
			leaf_index,
			tree_depth,
			tree_id,
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
			return Err(pool_is_empty());
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

		// Nullifier count — O(1) read of TotalNullifiersSpent counter.
		// Defaults to 0 if the storage item is absent (pool with no spent notes yet).
		let nullifier_count =
			match read_storage(&*self.client, best_hash, value_key(b"TotalNullifiersSpent"))? {
				Some(raw) => u64::decode(&mut &raw[..]).unwrap_or(0),
				None => 0,
			};

		Ok(PoolStatsResponse {
			merkle_root: format!("0x{}", hex::encode(root.as_bytes())),
			commitment_count,
			nullifier_count,
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
				tree_id: 0,
			};
			let json = serde_json::to_value(&resp).unwrap();
			assert_eq!(json["root"], "0xaabb");
			assert_eq!(json["leaf_index"], 7);
			assert_eq!(json["tree_depth"], 20);
			assert_eq!(json["tree_id"], 0);
			assert_eq!(json["path"].as_array().unwrap().len(), 2);
		}

		#[test]
		fn merkle_proof_response_round_trips_serde() {
			let orig = MerkleProofResponse {
				root: "0x00".to_string(),
				path: vec!["0xaa".to_string()],
				leaf_index: 3,
				tree_depth: 20,
				tree_id: 0,
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
				nullifier_count: 3,
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
			assert_eq!(json["nullifier_count"], 3u64);
			// balance fields are serialised as decimal strings to preserve JS precision.
			assert_eq!(json["total_balance"].as_str().unwrap(), "1000");
			let ab = json["asset_balances"].as_array().unwrap();
			assert_eq!(ab.len(), 2);
			assert_eq!(ab[0]["asset_id"], 0u64);
			assert_eq!(ab[0]["balance"].as_str().unwrap(), "600");
		}

		#[test]
		fn pool_stats_response_round_trips_serde() {
			let orig = PoolStatsResponse {
				merkle_root: "0xff".to_string(),
				commitment_count: 1,
				nullifier_count: 0,
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

		#[test]
		fn pool_stats_response_nullifier_count_field_present() {
			let resp = PoolStatsResponse {
				merkle_root: "0xab".to_string(),
				commitment_count: 10,
				nullifier_count: 4,
				total_balance: 0,
				asset_balances: vec![],
				tree_depth: 20,
			};
			let json = serde_json::to_value(&resp).unwrap();
			// nullifier_count must be present and correctly serialised
			assert_eq!(json["nullifier_count"], 4u64);
			// active notes estimate: commitment_count - nullifier_count
			let active = json["commitment_count"].as_u64().unwrap()
				- json["nullifier_count"].as_u64().unwrap();
			assert_eq!(active, 6);
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

	// -------------------------------------------------------------------------
	// Error constructors
	// -------------------------------------------------------------------------

	mod error_constructors {
		use super::*;
		use jsonrpsee::types::error::ErrorCode;

		#[test]
		fn pool_not_initialized_uses_internal_error_code() {
			let e = pool_not_initialized();
			assert_eq!(e.code(), ErrorCode::InternalError.code());
		}

		#[test]
		fn pool_is_empty_uses_internal_error_code() {
			let e = pool_is_empty();
			assert_eq!(e.code(), ErrorCode::InternalError.code());
		}

		#[test]
		fn pool_is_empty_message_differs_from_not_initialized() {
			let empty = pool_is_empty();
			let uninit = pool_not_initialized();
			// Must produce distinct messages so callers can distinguish the two states.
			assert_ne!(empty.message(), uninit.message());
		}
	}
}
