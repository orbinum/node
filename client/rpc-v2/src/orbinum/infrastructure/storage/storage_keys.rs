//! Storage keys - Building storage keys for `pallet-shielded-pool`
//!
//! Substrate uses `blake2_128_concat` hashing for storage maps.
//! Each key is built as: `twox_128(pallet) + twox_128(item) + blake2_128_concat(key)`

use sp_core::{
	hashing::{blake2_128, twox_128},
	H256,
};

/// Shielded pool pallet identifier.
const PALLET_SHIELDED_POOL: &[u8] = b"ShieldedPool";

/// Builds the storage key for `PoseidonRoot` (`StorageValue<H256>`).
///
/// # Storage Item
/// `pallet_shielded_pool::PoseidonRoot::<T>`
///
/// # Returns
/// `twox_128("ShieldedPool") + twox_128("PoseidonRoot")`
pub fn merkle_root() -> Vec<u8> {
	twox_128(PALLET_SHIELDED_POOL)
		.iter()
		.chain(twox_128(b"PoseidonRoot").iter())
		.copied()
		.collect()
}

/// Builds the storage key for `MerkleTreeSize` (`StorageValue<u32>`).
///
/// # Storage Item
/// `pallet_shielded_pool::MerkleTreeSize::<T>`
///
/// # Returns
/// `twox_128("ShieldedPool") + twox_128("MerkleTreeSize")`
pub fn merkle_tree_size() -> Vec<u8> {
	twox_128(PALLET_SHIELDED_POOL)
		.iter()
		.chain(twox_128(b"MerkleTreeSize").iter())
		.copied()
		.collect()
}

/// Builds the storage key for `MerkleLeaves` map (`StorageMap<u32, H256>`).
///
/// # Storage Item
/// `pallet_shielded_pool::MerkleLeaves::<T>::get(index)`
///
/// # Parameters
/// - `index`: Leaf index (`u32`)
///
/// # Returns
/// `twox_128("ShieldedPool") + twox_128("MerkleLeaves") + blake2_128_concat(index)`
pub fn merkle_leaf(index: u32) -> Vec<u8> {
	let mut key = twox_128(PALLET_SHIELDED_POOL)
		.iter()
		.chain(twox_128(b"MerkleLeaves").iter())
		.copied()
		.collect::<Vec<_>>();

	// blake2_128_concat = 16-byte hash + original data
	let index_bytes = index.to_le_bytes();
	key.extend_from_slice(&blake2_128_concat(&index_bytes));
	key
}

/// Builds the storage key for `PoolBalance` (`StorageValue<Balance>`).
///
/// # Storage Item
/// `pallet_shielded_pool::PoolBalance::<T>`
///
/// # Returns
/// `twox_128("ShieldedPool") + twox_128("PoolBalance")`
pub fn pool_balance() -> Vec<u8> {
	twox_128(PALLET_SHIELDED_POOL)
		.iter()
		.chain(twox_128(b"PoolBalance").iter())
		.copied()
		.collect()
}

/// Builds the storage key for `PoolBalancePerAsset` map (`StorageMap<AssetId, Balance>`).
///
/// # Storage Item
/// `pallet_shielded_pool::PoolBalancePerAsset::<T>::get(asset_id)`
///
/// # Parameters
/// - `asset_id`: Asset ID (`u32`)
///
/// # Returns
/// `twox_128("ShieldedPool") + twox_128("PoolBalancePerAsset") + blake2_128_concat(asset_id)`
pub fn pool_balance_per_asset(asset_id: u32) -> Vec<u8> {
	let mut key = twox_128(PALLET_SHIELDED_POOL)
		.iter()
		.chain(twox_128(b"PoolBalancePerAsset").iter())
		.copied()
		.collect::<Vec<_>>();

	let asset_id_bytes = asset_id.to_le_bytes();
	key.extend_from_slice(&blake2_128_concat(&asset_id_bytes));
	key
}

/// Builds the storage key for `NullifierSet` map (`StorageMap<H256, ()>`).
///
/// # Storage Item
/// `pallet_shielded_pool::NullifierSet::<T>::contains_key(nullifier)`
///
/// # Parameters
/// - `nullifier`: Nullifier hash (`H256`)
///
/// # Returns
/// `twox_128("ShieldedPool") + twox_128("NullifierSet") + blake2_128_concat(nullifier)`
pub fn nullifier_spent(nullifier: &H256) -> Vec<u8> {
	let mut key = twox_128(PALLET_SHIELDED_POOL)
		.iter()
		.chain(twox_128(b"NullifierSet").iter())
		.copied()
		.collect::<Vec<_>>();

	key.extend_from_slice(&blake2_128_concat(nullifier.as_bytes()));
	key
}

/// Helper: `blake2_128_concat` hashing.
///
/// # Algorithm
/// ```text
/// hash = blake2_128(data)  // 16 bytes
/// result = hash + data     // 16 bytes + original data
/// ```
fn blake2_128_concat(data: &[u8]) -> Vec<u8> {
	let hash = blake2_128(data);
	hash.iter().chain(data.iter()).copied().collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_build_merkle_root_key_with_expected_prefix_and_length() {
		let key = merkle_root();
		let expected_prefix = [twox_128(PALLET_SHIELDED_POOL), twox_128(b"PoseidonRoot")].concat();

		// Must contain exactly two twox_128 segments.
		assert_eq!(key.len(), 32);
		assert_eq!(key, expected_prefix);
	}

	#[test]
	fn should_build_merkle_leaf_key_with_expected_length_and_different_indices() {
		let key0 = merkle_leaf(0);
		let key1 = merkle_leaf(1);

		// 32 bytes prefix + 16-byte hash + 4-byte index
		assert_eq!(key0.len(), 52);
		assert_eq!(key1.len(), 52);
		assert_ne!(key0, key1);
		assert_eq!(
			&key0[..32],
			[twox_128(PALLET_SHIELDED_POOL), twox_128(b"MerkleLeaves")].concat()
		);
	}

	#[test]
	fn should_build_nullifier_key_with_expected_length() {
		let nullifier = H256::from([42u8; 32]);
		let key = nullifier_spent(&nullifier);
		// 32 bytes prefix + 16-byte hash + 32-byte nullifier
		assert_eq!(key.len(), 80);
	}

	#[test]
	fn should_build_pool_balance_keys_with_expected_lengths() {
		let total = pool_balance();
		let per_asset = pool_balance_per_asset(7);

		assert_eq!(total.len(), 32);
		assert_eq!(per_asset.len(), 52);
	}
}
