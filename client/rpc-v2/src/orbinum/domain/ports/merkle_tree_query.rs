//! MerkleTreeQuery port - Interface for Merkle tree queries

use crate::orbinum::domain::{BlockHash, Commitment, DomainResult, TreeSize};

/// Port for querying the shielded pool Merkle tree.
///
/// Abstracts access to `pallet-shielded-pool` storage without
/// directly depending on FRAME storage types.
pub trait MerkleTreeQuery: Send + Sync {
	/// Returns the current Merkle tree root.
	///
	/// # Parameters
	/// - `block_hash`: Block hash to query
	///
	/// # Returns
	/// - Commitment representing the tree root
	fn get_merkle_root(&self, block_hash: BlockHash) -> DomainResult<Commitment>;

	/// Returns tree size (number of leaves/commitments).
	///
	/// # Parameters
	/// - `block_hash`: Block hash to query
	///
	/// # Returns
	/// - Number of leaves in the tree
	fn get_tree_size(&self, block_hash: BlockHash) -> DomainResult<TreeSize>;

	/// Returns a leaf (commitment) at a specific index.
	///
	/// # Parameters
	/// - `block_hash`: Block hash to query
	/// - `leaf_index`: Leaf index (0-indexed)
	///
	/// # Returns
	/// - Commitment at that index
	/// - Error if index is out of bounds
	fn get_leaf(&self, block_hash: BlockHash, leaf_index: u32) -> DomainResult<Commitment>;

	/// Checks whether the tree is initialized.
	///
	/// # Parameters
	/// - `block_hash`: Block hash to query
	///
	/// # Returns
	/// - `true` if tree has at least one leaf
	/// - `false` if tree is empty
	fn is_initialized(&self, block_hash: BlockHash) -> DomainResult<bool> {
		let size = self.get_tree_size(block_hash)?;
		Ok(size.value() > 0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Clone, Copy)]
	struct MockMerkleTreeQuery {
		tree_size: u32,
	}

	impl MerkleTreeQuery for MockMerkleTreeQuery {
		fn get_merkle_root(&self, _block_hash: BlockHash) -> DomainResult<Commitment> {
			Ok(Commitment::new([0x33u8; 32]))
		}

		fn get_tree_size(&self, _block_hash: BlockHash) -> DomainResult<TreeSize> {
			Ok(TreeSize::new(self.tree_size))
		}

		fn get_leaf(&self, _block_hash: BlockHash, leaf_index: u32) -> DomainResult<Commitment> {
			Ok(Commitment::new([leaf_index as u8; 32]))
		}
	}

	#[test]
	fn should_query_merkle_root_and_leaf() {
		let query = MockMerkleTreeQuery { tree_size: 2 };
		let block_hash = BlockHash::new([1u8; 32]);

		let root = query
			.get_merkle_root(block_hash)
			.expect("root query should succeed");
		let leaf = query
			.get_leaf(block_hash, 7)
			.expect("leaf query should succeed");

		assert_eq!(root, Commitment::new([0x33u8; 32]));
		assert_eq!(leaf, Commitment::new([7u8; 32]));
	}

	#[test]
	fn should_use_default_is_initialized_based_on_tree_size() {
		let block_hash = BlockHash::new([2u8; 32]);
		let initialized = MockMerkleTreeQuery { tree_size: 1 };
		let empty = MockMerkleTreeQuery { tree_size: 0 };

		assert!(initialized
			.is_initialized(block_hash)
			.expect("is_initialized should succeed"));
		assert!(!empty
			.is_initialized(block_hash)
			.expect("is_initialized should succeed"));
	}
}
