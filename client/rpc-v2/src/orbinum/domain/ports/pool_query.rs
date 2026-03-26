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

	/// Returns non-zero balances for all known assets in the pool.
	fn get_all_asset_balances(
		&self,
		block_hash: BlockHash,
	) -> DomainResult<Vec<(AssetId, PoolBalance)>>;
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

		fn get_all_asset_balances(
			&self,
			_block_hash: BlockHash,
		) -> DomainResult<Vec<(AssetId, PoolBalance)>> {
			Ok(vec![(AssetId::new(0), 1_000), (AssetId::new(7), 700)])
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

	#[test]
	fn should_query_all_asset_balances() {
		let query = MockPoolQuery;
		let block_hash = BlockHash::new([6u8; 32]);

		let balances = query
			.get_all_asset_balances(block_hash)
			.expect("all asset balances query should succeed");

		assert_eq!(
			balances,
			vec![(AssetId::new(0), 1_000), (AssetId::new(7), 700)]
		);
	}
}
