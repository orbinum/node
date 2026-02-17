//! PoolStatsHandler - Handler to fetch pool statistics

use std::sync::Arc;

use jsonrpsee::core::RpcResult;

use crate::orbinum::{
	application::{PoolQueryService, PoolStatsResponse},
	infrastructure::mappers::CommitmentMapper,
	presentation::validation::RpcError,
};

/// Handler for `privacy_getPoolStats`.
pub struct PoolStatsHandler<Q> {
	pool_service: Arc<PoolQueryService<Q>>,
}

impl<Q> PoolStatsHandler<Q>
where
	Q: crate::orbinum::domain::BlockchainQuery
		+ crate::orbinum::domain::MerkleTreeQuery
		+ crate::orbinum::domain::PoolQuery,
{
	/// Creates a new `PoolStatsHandler`.
	pub fn new(pool_service: Arc<PoolQueryService<Q>>) -> Self {
		Self { pool_service }
	}

	/// Handles request to fetch pool statistics.
	///
	/// # Returns
	/// - `PoolStatsResponse`: DTO with all pool statistics
	///
	/// # Errors
	/// - `PoolNotInitialized`: If pool is not initialized
	pub fn handle(&self) -> RpcResult<PoolStatsResponse> {
		// 1. Fetch statistics from service
		let stats = self
			.pool_service
			.get_statistics()
			.map_err(RpcError::from_application_error)?;

		// 2. Map domain entity to DTO
		let merkle_root_hex = CommitmentMapper::to_hex_string(stats.merkle_root());

		let response = PoolStatsResponse::new(
			merkle_root_hex,
			stats.commitment_count().value(),
			stats.total_balance(),
			stats.tree_depth().value(),
		);

		Ok(response)
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
		total_balance: u128,
	}

	impl BlockchainQuery for MockQuery {
		fn best_hash(&self) -> DomainResult<BlockHash> {
			Ok(BlockHash::new([5u8; 32]))
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
			Ok(self.total_balance)
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
	fn should_return_pool_stats_response() {
		let query = MockQuery {
			root: Commitment::new([0xCCu8; 32]),
			tree_size: 8,
			total_balance: 1_234,
		};
		let service = Arc::new(PoolQueryService::new(query));
		let handler = PoolStatsHandler::new(service);

		let response = handler.handle().expect("handler should succeed");

		assert_eq!(response.merkle_root, format!("0x{}", "cc".repeat(32)));
		assert_eq!(response.commitment_count, 8);
		assert_eq!(response.total_balance, 1_234);
		assert_eq!(
			response.tree_depth,
			crate::orbinum::domain::TreeDepth::from_tree_size(8).value()
		);
	}

	#[test]
	fn should_fail_when_pool_not_initialized() {
		let query = MockQuery {
			root: Commitment::new([0xCCu8; 32]),
			tree_size: 0,
			total_balance: 0,
		};
		let service = Arc::new(PoolQueryService::new(query));
		let handler = PoolStatsHandler::new(service);

		let result = handler.handle();

		assert!(result.is_err());
	}
}
