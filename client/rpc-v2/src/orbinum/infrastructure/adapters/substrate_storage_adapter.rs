//! SubstrateStorageAdapter - Implements ports using a Substrate client

use sc_client_api::StorageProvider as ScStorageProvider;
use scale_codec::Decode;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::{marker::PhantomData, sync::Arc};

use crate::orbinum::{
	domain::{
		AssetId, BlockHash, BlockchainQuery, Commitment, DomainError, DomainResult,
		MerkleTreeQuery, Nullifier, NullifierQuery, PoolQuery, TreeSize,
	},
	infrastructure::{mappers::DomainMapper, storage::storage_keys},
};

/// Substrate storage adapter implementing all domain ports.
///
/// This adapter connects domain ports to the Substrate client,
/// enabling runtime storage queries for `pallet-shielded-pool`.
///
/// # Generics
/// - `C`: Substrate client (`HeaderBackend` + `StorageProvider`)
/// - `B`: Block type
/// - `BE`: Storage backend type
pub struct SubstrateStorageAdapter<C, B, BE> {
	client: Arc<C>,
	_marker: PhantomData<(B, BE)>,
}

impl<C, B, BE> Clone for SubstrateStorageAdapter<C, B, BE> {
	fn clone(&self) -> Self {
		Self {
			client: self.client.clone(),
			_marker: PhantomData,
		}
	}
}

impl<C, B, BE> SubstrateStorageAdapter<C, B, BE> {
	/// Creates a new `SubstrateStorageAdapter`.
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			_marker: PhantomData,
		}
	}
}

// ============================================================================
// BlockchainQuery implementation
// ============================================================================

impl<C, B, BE> BlockchainQuery for SubstrateStorageAdapter<C, B, BE>
where
	C: HeaderBackend<B> + ScStorageProvider<B, BE> + Send + Sync,
	B: BlockT,
	BE: sc_client_api::Backend<B> + Send + Sync,
{
	fn best_hash(&self) -> DomainResult<BlockHash> {
		let best_hash = self.client.info().best_hash;
		let bytes: [u8; 32] = best_hash
			.as_ref()
			.try_into()
			.map_err(|_| DomainError::CalculationError("Invalid block hash length".to_string()))?;
		Ok(BlockHash::new(bytes))
	}

	fn storage_at(
		&self,
		block_hash: BlockHash,
		storage_key: &[u8],
	) -> DomainResult<Option<Vec<u8>>> {
		// Convert domain `BlockHash` to Substrate hash
		let block_h256 = sp_core::H256::from_slice(block_hash.as_bytes());
		let hash = <B as BlockT>::Hash::decode(&mut block_h256.as_bytes())
			.map_err(|_| DomainError::CalculationError("Invalid block hash".to_string()))?;

		// Convert `storage_key` into Substrate `StorageKey`
		let storage_key = sp_core::storage::StorageKey(storage_key.to_vec());

		// Query storage using the trait explicitly
		ScStorageProvider::storage(&*self.client, hash, &storage_key)
			.map_err(|e| DomainError::StorageDecodeError(format!("Storage error: {e:?}")))?
			.map(|data| Ok(data.0))
			.transpose()
	}
}

// ============================================================================
// MerkleTreeQuery implementation
// ============================================================================

impl<C, B, BE> MerkleTreeQuery for SubstrateStorageAdapter<C, B, BE>
where
	C: HeaderBackend<B> + ScStorageProvider<B, BE> + Send + Sync,
	B: BlockT,
	BE: sc_client_api::Backend<B> + Send + Sync,
{
	fn get_merkle_root(&self, block_hash: BlockHash) -> DomainResult<Commitment> {
		let storage_key = storage_keys::merkle_root();
		let data = self
			.storage_at(block_hash, &storage_key)?
			.ok_or(DomainError::MerkleTreeNotInitialized)?;

		// Decode `H256` and map to domain `Commitment`
		let h256 = sp_core::H256::decode(&mut &data[..]).map_err(|e| {
			DomainError::StorageDecodeError(format!("Failed to decode merkle root: {e}"))
		})?;

		Ok(DomainMapper::h256_to_commitment(h256))
	}

	fn get_tree_size(&self, block_hash: BlockHash) -> DomainResult<TreeSize> {
		let storage_key = storage_keys::merkle_tree_size();
		let data = self
			.storage_at(block_hash, &storage_key)?
			.ok_or(DomainError::MerkleTreeNotInitialized)?;

		// Decode `u32`
		let size = u32::decode(&mut &data[..]).map_err(|e| {
			DomainError::StorageDecodeError(format!("Failed to decode tree size: {e}"))
		})?;

		Ok(TreeSize::new(size))
	}

	fn get_leaf(&self, block_hash: BlockHash, leaf_index: u32) -> DomainResult<Commitment> {
		let storage_key = storage_keys::merkle_leaf(leaf_index);
		let data = self.storage_at(block_hash, &storage_key)?.ok_or(
			DomainError::LeafIndexOutOfBounds {
				index: leaf_index,
				tree_size: 0,
			},
		)?;

		// Decode `H256` and map to `Commitment`
		let h256 = sp_core::H256::decode(&mut &data[..])
			.map_err(|e| DomainError::StorageDecodeError(format!("Failed to decode leaf: {e}")))?;

		Ok(DomainMapper::h256_to_commitment(h256))
	}
}

// ============================================================================
// NullifierQuery implementation
// ============================================================================

impl<C, B, BE> NullifierQuery for SubstrateStorageAdapter<C, B, BE>
where
	C: HeaderBackend<B> + ScStorageProvider<B, BE> + Send + Sync,
	B: BlockT,
	BE: sc_client_api::Backend<B> + Send + Sync,
{
	fn is_nullifier_spent(
		&self,
		block_hash: BlockHash,
		nullifier: Nullifier,
	) -> DomainResult<bool> {
		// Convert domain `Nullifier` to `H256`
		let nullifier_h256 = DomainMapper::nullifier_to_h256(nullifier);

		let storage_key = storage_keys::nullifier_spent(&nullifier_h256);
		let data = self.storage_at(block_hash, &storage_key)?;

		// If any data exists in storage, the nullifier is spent
		Ok(data.is_some())
	}
}

// ============================================================================
// PoolQuery implementation
// ============================================================================

impl<C, B, BE> PoolQuery for SubstrateStorageAdapter<C, B, BE>
where
	C: HeaderBackend<B> + ScStorageProvider<B, BE> + Send + Sync,
	B: BlockT,
	BE: sc_client_api::Backend<B> + Send + Sync,
{
	fn get_total_balance(&self, block_hash: BlockHash) -> DomainResult<u128> {
		let storage_key = storage_keys::pool_balance();
		let data = self
			.storage_at(block_hash, &storage_key)?
			.ok_or(DomainError::PoolNotInitialized)?;

		// Decode balance (`u128`)
		let balance = u128::decode(&mut &data[..]).map_err(|e| {
			DomainError::StorageDecodeError(format!("Failed to decode pool balance: {e}"))
		})?;

		Ok(balance)
	}

	fn get_asset_balance(&self, block_hash: BlockHash, asset_id: AssetId) -> DomainResult<u128> {
		let storage_key = storage_keys::pool_balance_per_asset(asset_id.0);
		let data = self.storage_at(block_hash, &storage_key)?;

		// If storage entry does not exist, balance is `0`
		let balance = if let Some(data) = data {
			u128::decode(&mut &data[..]).map_err(|e| {
				DomainError::StorageDecodeError(format!("Failed to decode asset balance: {e}"))
			})?
		} else {
			0u128
		};

		Ok(balance)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Default)]
	struct DummyClient;

	#[test]
	fn should_create_adapter_with_new() {
		let client = Arc::new(DummyClient);
		let _adapter: SubstrateStorageAdapter<DummyClient, (), ()> =
			SubstrateStorageAdapter::new(client);
	}

	#[test]
	fn should_clone_adapter_sharing_same_client_arc() {
		let client = Arc::new(DummyClient);
		let adapter: SubstrateStorageAdapter<DummyClient, (), ()> =
			SubstrateStorageAdapter::new(client.clone());
		assert_eq!(Arc::strong_count(&client), 2);

		let cloned = adapter.clone();
		let _ = cloned;

		assert_eq!(Arc::strong_count(&client), 3);
	}
}
