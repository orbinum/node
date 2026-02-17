//! PoolStatistics entity - Shielded pool statistics

use crate::orbinum::domain::{ports::PoolBalance, Commitment, TreeDepth, TreeSize};

/// Aggregated shielded pool statistics.
///
/// Entity that encapsulates all relevant pool metrics
/// at a specific point in time (snapshot at a block).
///
/// # Components
/// - `merkle_root`: Current Merkle tree root
/// - `commitment_count`: Total number of commitments in the tree
/// - `total_balance`: Total pool balance (all assets)
/// - `tree_depth`: Merkle tree depth
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolStatistics {
	/// Merkle tree root.
	merkle_root: Commitment,
	/// Number of commitments in the tree.
	commitment_count: TreeSize,
	/// Total pool balance.
	total_balance: PoolBalance,
	/// Tree depth.
	tree_depth: TreeDepth,
}

impl PoolStatistics {
	/// Creates a new `PoolStatistics` instance.
	///
	/// # Parameters
	/// - `merkle_root`: Merkle tree root
	/// - `commitment_count`: Number of commitments
	/// - `total_balance`: Total balance
	/// - `tree_depth`: Tree depth
	pub fn new(
		merkle_root: Commitment,
		commitment_count: TreeSize,
		total_balance: PoolBalance,
		tree_depth: TreeDepth,
	) -> Self {
		Self {
			merkle_root,
			commitment_count,
			total_balance,
			tree_depth,
		}
	}

	/// Returns the tree root.
	pub fn merkle_root(&self) -> Commitment {
		self.merkle_root
	}

	/// Returns the number of commitments.
	pub fn commitment_count(&self) -> TreeSize {
		self.commitment_count
	}

	/// Returns the total balance.
	pub fn total_balance(&self) -> PoolBalance {
		self.total_balance
	}

	/// Returns the tree depth.
	pub fn tree_depth(&self) -> TreeDepth {
		self.tree_depth
	}

	/// Checks if the pool is initialized (at least one commitment).
	pub fn is_initialized(&self) -> bool {
		self.commitment_count.value() > 0
	}

	/// Checks if the pool is empty.
	pub fn is_empty(&self) -> bool {
		self.commitment_count.value() == 0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_and_read_pool_statistics() {
		let root = Commitment::new([4u8; 32]);
		let stats = PoolStatistics::new(root, TreeSize::new(10), 2_500, TreeDepth::new(4));

		assert_eq!(stats.merkle_root(), root);
		assert_eq!(stats.commitment_count().value(), 10);
		assert_eq!(stats.total_balance(), 2_500);
		assert_eq!(stats.tree_depth().value(), 4);
	}

	#[test]
	fn should_report_initialized_and_empty_flags() {
		let initialized = PoolStatistics::new(
			Commitment::new([1u8; 32]),
			TreeSize::new(1),
			100,
			TreeDepth::new(1),
		);
		let empty = PoolStatistics::new(
			Commitment::new([2u8; 32]),
			TreeSize::new(0),
			0,
			TreeDepth::new(0),
		);

		assert!(initialized.is_initialized());
		assert!(!initialized.is_empty());
		assert!(!empty.is_initialized());
		assert!(empty.is_empty());
	}
}
