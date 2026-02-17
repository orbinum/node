//! PoolQuery port - Interface for pool statistics queries

use crate::orbinum::domain::{AssetId, BlockHash, DomainResult};

/// Pool balance type alias.
pub type PoolBalance = u128;

/// Port for querying shielded pool statistics.
///
/// Abstracts access to storage items related to balances and pool state.
pub trait PoolQuery: Send + Sync {
	/// Returns the total pool balance.
	///
	/// # Parameters
	/// - `block_hash`: Block hash to query
	///
	/// # Returns
	/// - Total balance in the pool (sum of all assets)
	fn get_total_balance(&self, block_hash: BlockHash) -> DomainResult<PoolBalance>;

	/// Returns balance for a specific asset.
	///
	/// # Parameters
	/// - `block_hash`: Block hash to query
	/// - `asset_id`: Asset ID
	///
	/// # Returns
	/// - Asset balance in the pool
	fn get_asset_balance(
		&self,
		block_hash: BlockHash,
		asset_id: AssetId,
	) -> DomainResult<PoolBalance>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Clone, Copy)]
	struct MockPoolQuery;

	impl PoolQuery for MockPoolQuery {
		fn get_total_balance(&self, _block_hash: BlockHash) -> DomainResult<PoolBalance> {
			Ok(1_000)
		}

		fn get_asset_balance(
			&self,
			_block_hash: BlockHash,
			asset_id: AssetId,
		) -> DomainResult<PoolBalance> {
			Ok((asset_id.inner() as u128) * 100)
		}
	}

	#[test]
	fn should_query_total_balance() {
		let query = MockPoolQuery;
		let block_hash = BlockHash::new([4u8; 32]);

		let balance = query
			.get_total_balance(block_hash)
			.expect("total balance query should succeed");

		assert_eq!(balance, 1_000);
	}

	#[test]
	fn should_query_asset_balance() {
		let query = MockPoolQuery;
		let block_hash = BlockHash::new([5u8; 32]);

		let balance = query
			.get_asset_balance(block_hash, AssetId::new(7))
			.expect("asset balance query should succeed");

		assert_eq!(balance, 700);
	}
}
