//! NullifierService - Service for querying nullifier status

use crate::orbinum::{
	application::ApplicationResult,
	domain::{BlockchainQuery, Nullifier, NullifierQuery},
};

/// Service for querying nullifier status.
///
/// Coordinates `NullifierSet` storage queries through domain ports.
pub struct NullifierService<Q> {
	query: Q,
}

impl<Q> NullifierService<Q>
where
	Q: BlockchainQuery + NullifierQuery,
{
	/// Creates a new `NullifierService`.
	pub fn new(query: Q) -> Self {
		Self { query }
	}

	/// Checks whether a nullifier has been spent.
	///
	/// # Parameters
	/// - `nullifier`: Nullifier to check
	///
	/// # Returns
	/// - `true`: Nullifier is already spent (`NullifierSet` contains it)
	/// - `false`: Nullifier is still available
	///
	/// # Errors
	/// - `PoolNotInitialized`: If pool is not initialized
	/// - `Domain`: Storage query errors
	pub fn is_spent(&self, nullifier: Nullifier) -> ApplicationResult<bool> {
		// 1. Get best block hash
		let block_hash = self.query.best_hash()?;

		// 2. Query whether nullifier exists in the set
		let is_spent = self.query.is_nullifier_spent(block_hash, nullifier)?;

		Ok(is_spent)
	}

	/// Checks multiple nullifiers in batch.
	///
	/// # Parameters
	/// - `nullifiers`: Nullifier list to check
	///
	/// # Returns
	/// - Vector of tuples (`nullifier`, `is_spent`)
	pub fn check_batch(
		&self,
		nullifiers: Vec<Nullifier>,
	) -> ApplicationResult<Vec<(Nullifier, bool)>> {
		let block_hash = self.query.best_hash()?;

		let results = nullifiers
			.into_iter()
			.map(|n| {
				let is_spent = self.query.is_nullifier_spent(block_hash, n)?;
				Ok((n, is_spent))
			})
			.collect::<ApplicationResult<Vec<_>>>()?;

		Ok(results)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::{BlockHash, DomainResult};

	#[derive(Clone, Copy)]
	struct MockQuery;

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

	impl NullifierQuery for MockQuery {
		fn is_nullifier_spent(
			&self,
			_block_hash: BlockHash,
			nullifier: Nullifier,
		) -> DomainResult<bool> {
			Ok(nullifier.as_bytes()[0] == 1)
		}
	}

	#[test]
	fn should_check_single_nullifier_status() {
		let service = NullifierService::new(MockQuery);
		let spent = Nullifier::new([1u8; 32]);
		let available = Nullifier::new([0u8; 32]);

		assert!(service.is_spent(spent).expect("spent query must succeed"));
		assert!(!service
			.is_spent(available)
			.expect("available query must succeed"));
	}

	#[test]
	fn should_check_nullifiers_in_batch() {
		let service = NullifierService::new(MockQuery);
		let n1 = Nullifier::new([1u8; 32]);
		let n2 = Nullifier::new([0u8; 32]);

		let results = service
			.check_batch(vec![n1, n2])
			.expect("batch query must succeed");

		assert_eq!(results.len(), 2);
		assert_eq!(results[0], (n1, true));
		assert_eq!(results[1], (n2, false));
	}
}
