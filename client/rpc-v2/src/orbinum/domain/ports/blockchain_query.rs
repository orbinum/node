//! BlockchainQuery port - Interface for blockchain queries

use crate::orbinum::domain::{BlockHash, DomainResult};

/// Port for querying blockchain state.
///
/// This trait abstracts blockchain access without depending on
/// Substrate-specific types (`sp_blockchain`, `HeaderBackend`, etc.).
pub trait BlockchainQuery: Send + Sync {
	/// Returns the best (most recent) block hash.
	///
	/// # Returns
	/// - Most recent block hash (usually finalized or best)
	fn best_hash(&self) -> DomainResult<BlockHash>;

	/// Queries storage at a specific block.
	///
	/// # Parameters
	/// - `block_hash`: Block hash to query
	/// - `storage_key`: Storage key (raw bytes)
	///
	/// # Returns
	/// - `Some(Vec<u8>)`: Value found in storage (SCALE-encoded)
	/// - `None`: Key does not exist in storage
	fn storage_at(
		&self,
		block_hash: BlockHash,
		storage_key: &[u8],
	) -> DomainResult<Option<Vec<u8>>>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Clone, Copy)]
	struct MockBlockchainQuery;

	impl BlockchainQuery for MockBlockchainQuery {
		fn best_hash(&self) -> DomainResult<BlockHash> {
			Ok(BlockHash::new([0x11u8; 32]))
		}

		fn storage_at(
			&self,
			_block_hash: BlockHash,
			storage_key: &[u8],
		) -> DomainResult<Option<Vec<u8>>> {
			if storage_key == b"exists" {
				Ok(Some(vec![1, 2, 3]))
			} else {
				Ok(None)
			}
		}
	}

	#[test]
	fn should_return_best_hash() {
		let query = MockBlockchainQuery;
		let hash = query.best_hash().expect("best_hash should succeed");

		assert_eq!(hash, BlockHash::new([0x11u8; 32]));
	}

	#[test]
	fn should_query_storage_at_block() {
		let query = MockBlockchainQuery;
		let block_hash = BlockHash::new([0x22u8; 32]);

		let found = query
			.storage_at(block_hash, b"exists")
			.expect("storage query should succeed");
		let missing = query
			.storage_at(block_hash, b"missing")
			.expect("storage query should succeed");

		assert_eq!(found, Some(vec![1, 2, 3]));
		assert_eq!(missing, None);
	}
}
