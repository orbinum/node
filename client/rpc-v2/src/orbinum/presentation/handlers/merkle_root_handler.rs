//! MerkleRootHandler - Handler to fetch the Merkle root

use std::sync::Arc;

use jsonrpsee::core::RpcResult;

use crate::orbinum::{
	application::PoolQueryService, infrastructure::mappers::CommitmentMapper,
	presentation::validation::RpcError,
};

/// Handler for `privacy_getMerkleRoot`.
pub struct MerkleRootHandler<Q> {
	pool_service: Arc<PoolQueryService<Q>>,
}

impl<Q> MerkleRootHandler<Q>
where
	Q: crate::orbinum::domain::BlockchainQuery
		+ crate::orbinum::domain::MerkleTreeQuery
		+ crate::orbinum::domain::PoolQuery,
{
	/// Creates a new `MerkleRootHandler`.
	pub fn new(pool_service: Arc<PoolQueryService<Q>>) -> Self {
		Self { pool_service }
	}

	/// Handles request to fetch current Merkle root.
	///
	/// # Returns
	/// - `String`: Root hash as hex (`0x`-prefixed)
	///
	/// # Errors
	/// - `MerkleTreeNotInitialized`: If tree is not initialized
	pub fn handle(&self) -> RpcResult<String> {
		// 1. Fetch root from service
		let root = self
			.pool_service
			.get_merkle_root()
			.map_err(RpcError::from_application_error)?;

		// 2. Convert to hex string
		let root_hex = CommitmentMapper::to_hex_string(root);

		Ok(root_hex)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::{
		AssetId, BlockHash, BlockchainQuery, Commitment, DomainResult, MerkleTreeQuery, PoolQuery,
		TreeSize,
	};

	#[derive(Clone, Copy)]
	struct MockQuery {
		root: Commitment,
		tree_size: u32,
	}

	impl BlockchainQuery for MockQuery {
		fn best_hash(&self) -> DomainResult<BlockHash> {
			Ok(BlockHash::new([1u8; 32]))
		}

		fn storage_at(
			&self,
			_block_hash: BlockHash,
			_storage_key: &[u8],
		) -> DomainResult<Option<Vec<u8>>> {
			Ok(None)
		}
	}

	impl MerkleTreeQuery for MockQuery {
		fn get_merkle_root(&self, _block_hash: BlockHash) -> DomainResult<Commitment> {
			Ok(self.root)
		}

		fn get_tree_size(&self, _block_hash: BlockHash) -> DomainResult<TreeSize> {
			Ok(TreeSize::new(self.tree_size))
		}

		fn get_leaf(&self, _block_hash: BlockHash, _leaf_index: u32) -> DomainResult<Commitment> {
			Ok(Commitment::new([0u8; 32]))
		}
	}

	impl PoolQuery for MockQuery {
		fn get_total_balance(&self, _block_hash: BlockHash) -> DomainResult<u128> {
			Ok(0)
		}

		fn get_asset_balance(
			&self,
			_block_hash: BlockHash,
			_asset_id: AssetId,
		) -> DomainResult<u128> {
			Ok(0)
		}
	}

	#[test]
	fn should_return_hex_merkle_root() {
		let query = MockQuery {
			root: Commitment::new([0xAAu8; 32]),
			tree_size: 1,
		};
		let service = Arc::new(PoolQueryService::new(query));
		let handler = MerkleRootHandler::new(service);

		let result = handler.handle().expect("handler should succeed");

		assert_eq!(result, format!("0x{}", "aa".repeat(32)));
	}
}
