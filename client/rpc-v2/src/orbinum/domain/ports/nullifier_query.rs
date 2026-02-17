//! NullifierQuery port - Interface for nullifier queries

use crate::orbinum::domain::{BlockHash, DomainResult, Nullifier};

/// Port for querying nullifier status.
///
/// Nullifiers prevent double-spending by marking notes as spent.
/// This trait abstracts access to pallet `NullifierSet` storage.
pub trait NullifierQuery: Send + Sync {
	/// Checks whether a nullifier has been spent.
	///
	/// # Parameters
	/// - `block_hash`: Block hash to query
	/// - `nullifier`: Nullifier to check
	///
	/// # Returns
	/// - `true` if nullifier exists in the set (already spent)
	/// - `false` if nullifier is still available
	fn is_nullifier_spent(&self, block_hash: BlockHash, nullifier: Nullifier)
		-> DomainResult<bool>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Clone, Copy)]
	struct MockNullifierQuery;

	impl NullifierQuery for MockNullifierQuery {
		fn is_nullifier_spent(
			&self,
			_block_hash: BlockHash,
			nullifier: Nullifier,
		) -> DomainResult<bool> {
			Ok(nullifier.as_bytes()[0] == 0xFF)
		}
	}

	#[test]
	fn should_check_nullifier_status() {
		let query = MockNullifierQuery;
		let block_hash = BlockHash::new([3u8; 32]);
		let spent = Nullifier::new([0xFFu8; 32]);
		let available = Nullifier::new([0x01u8; 32]);

		assert!(query
			.is_nullifier_spent(block_hash, spent)
			.expect("nullifier query should succeed"));
		assert!(!query
			.is_nullifier_spent(block_hash, available)
			.expect("nullifier query should succeed"));
	}
}
