//! PoolQueryService - Service for querying pool statistics

use crate::orbinum::{
	application::{ApplicationError, ApplicationResult},
	domain::{
		AssetId, BlockchainQuery, Commitment, MerkleTreeQuery, PoolQuery, PoolStatistics,
		TreeDepth, TreeSize,
	},
};

/// Service for querying shielded pool statistics.
///
/// Coordinates queries across multiple storage items and aggregates results.
pub struct PoolQueryService<Q> {
	query: Q,
}

impl<Q> PoolQueryService<Q>
where
	Q: BlockchainQuery + MerkleTreeQuery + PoolQuery,
{
	/// Creates a new `PoolQueryService`.
	pub fn new(query: Q) -> Self {
		Self { query }
	}

	/// Returns full pool statistics.
	///
	/// # Returns
	/// - `PoolStatistics`: Entity containing all pool metrics
	///
	/// # Errors
	/// - `PoolNotInitialized`: If the pool is not initialized
	/// - `Domain`: Storage query errors
	pub fn get_statistics(&self) -> ApplicationResult<PoolStatistics> {
		// 1. Get best block hash
		let block_hash = self.query.best_hash()?;

		// 2. Query Merkle root
		let merkle_root = self.query.get_merkle_root(block_hash)?;

		// 3. Query tree size (commitment count)
		let tree_size = self.query.get_tree_size(block_hash)?;

		// 4. Validate pool initialization
		if tree_size.value() == 0 {
			return Err(ApplicationError::PoolNotInitialized);
		}

		// 5. Query total balance
		let total_balance = self.query.get_total_balance(block_hash)?;

		// 6. Compute tree depth
		let tree_depth = TreeDepth::from_tree_size(tree_size.value());

		// 7. Build PoolStatistics
		Ok(PoolStatistics::new(
			merkle_root,
			tree_size,
			total_balance,
			tree_depth,
		))
	}

	/// Returns the current Merkle tree root.
	///
	/// # Returns
	/// - `Commitment`: Merkle root
	pub fn get_merkle_root(&self) -> ApplicationResult<Commitment> {
		let block_hash = self.query.best_hash()?;
		let root = self.query.get_merkle_root(block_hash)?;
		Ok(root)
	}

	/// Returns the number of commitments in the tree.
	///
	/// # Returns
	/// - `TreeSize`: Number of leaves
	pub fn get_commitment_count(&self) -> ApplicationResult<TreeSize> {
		let block_hash = self.query.best_hash()?;
		let size = self.query.get_tree_size(block_hash)?;
		Ok(size)
	}

	/// Returns the total pool balance.
	///
	/// # Returns
	/// - `u128`: Total balance in minimum units
	pub fn get_total_balance(&self) -> ApplicationResult<u128> {
		let block_hash = self.query.best_hash()?;
		let balance = self.query.get_total_balance(block_hash)?;
		Ok(balance)
	}

	/// Returns the balance for a specific asset.
	///
	/// # Parameters
	/// - `asset_id`: Asset identifier
	///
	/// # Returns
	/// - `u128`: Asset balance
	pub fn get_asset_balance(&self, asset_id: AssetId) -> ApplicationResult<u128> {
		let block_hash = self.query.best_hash()?;
		let balance = self.query.get_asset_balance(block_hash, asset_id)?;
		Ok(balance)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::{BlockHash, DomainResult};

	#[derive(Clone, Copy)]
	struct MockQuery {
		root: Commitment,
		tree_size: u32,
		total_balance: u128,
	}

	impl BlockchainQuery for MockQuery {
		fn best_hash(&self) -> DomainResult<BlockHash> {
			Ok(BlockHash::new([8u8; 32]))
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
			asset_id: AssetId,
		) -> DomainResult<u128> {
			Ok((asset_id.inner() as u128) * 10)
		}
	}

	#[test]
	fn should_return_pool_not_initialized_for_empty_tree() {
		let service = PoolQueryService::new(MockQuery {
			root: Commitment::new([1u8; 32]),
			tree_size: 0,
			total_balance: 100,
		});

		let result = service.get_statistics();

		assert!(matches!(result, Err(ApplicationError::PoolNotInitialized)));
	}

	#[test]
	fn should_return_full_pool_statistics() {
		let root = Commitment::new([3u8; 32]);
		let service = PoolQueryService::new(MockQuery {
			root,
			tree_size: 5,
			total_balance: 1_500,
		});

		let stats = service
			.get_statistics()
			.expect("statistics query must succeed");

		assert_eq!(stats.merkle_root(), root);
		assert_eq!(stats.commitment_count().value(), 5);
		assert_eq!(stats.total_balance(), 1_500);
		assert_eq!(
			stats.tree_depth().value(),
			TreeDepth::from_tree_size(5).value()
		);
	}

	#[test]
	fn should_return_single_metric_queries() {
		let root = Commitment::new([4u8; 32]);
		let service = PoolQueryService::new(MockQuery {
			root,
			tree_size: 9,
			total_balance: 999,
		});

		assert_eq!(
			service.get_merkle_root().expect("root query must succeed"),
			root
		);
		assert_eq!(
			service
				.get_commitment_count()
				.expect("size query must succeed")
				.value(),
			9
		);
		assert_eq!(
			service
				.get_total_balance()
				.expect("balance query must succeed"),
			999
		);
		assert_eq!(
			service
				.get_asset_balance(AssetId::new(7))
				.expect("asset balance query must succeed"),
			70
		);
	}
}
