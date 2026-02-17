//! MerkleProofService - Service for generating Merkle proofs

use crate::orbinum::{
	application::{ApplicationError, ApplicationResult},
	domain::{BlockchainQuery, Commitment, MerkleProofPath, MerkleTreeQuery, TreeDepth, TreeSize},
};

// Import zero-hash function from the pallet
use pallet_shielded_pool::infrastructure::merkle_tree::get_zero_hash_cached;

// Logging
extern crate log;

/// Service for generating Merkle proofs.
///
/// This service coordinates proof generation using:
/// - `BlockchainQuery`: to obtain the best block hash
/// - `MerkleTreeQuery`: to access Merkle tree leaves
///
/// # Algorithm
/// 1. Get `best_hash` from the blockchain
/// 2. Validate `leaf_index < tree_size`
/// 3. Traverse leaf-to-root collecting siblings
/// 4. Return `MerkleProofPath`
pub struct MerkleProofService<Q> {
	query: Q,
}

impl<Q> MerkleProofService<Q>
where
	Q: BlockchainQuery + MerkleTreeQuery,
{
	/// Creates a new `MerkleProofService`.
	pub fn new(query: Q) -> Self {
		Self { query }
	}

	/// Generates a Merkle proof for the given leaf index.
	///
	/// # Parameters
	/// - `leaf_index`: Leaf index (0-indexed)
	///
	/// # Returns
	/// - `MerkleProofPath`: Sibling path (20 elements for fixed depth)
	///
	/// # Errors
	/// - `InvalidLeafIndex`: If `leaf_index >= tree_size`
	/// - `TreeNotInitialized`: If the tree is empty
	/// - `Domain`: Storage query errors
	pub fn generate_proof(&self, leaf_index: u32) -> ApplicationResult<MerkleProofPath> {
		// 1. Get best block hash
		let block_hash = self.query.best_hash()?;

		// 2. Get tree size
		let tree_size = self.query.get_tree_size(block_hash)?;

		// 3. Validate tree initialization
		if tree_size.value() == 0 {
			return Err(ApplicationError::TreeNotInitialized);
		}

		// 4. Validate leaf index bounds
		if leaf_index >= tree_size.value() {
			return Err(ApplicationError::InvalidLeafIndex {
				index: leaf_index,
				tree_size: tree_size.value(),
			});
		}

		// 5. Build sibling path (with zero hashes up to depth 20)
		let path = self.collect_sibling_path(block_hash, leaf_index)?;

		// 6. Fixed tree depth for Sparse Merkle Tree
		let tree_depth = TreeDepth::new(20); // Fixed depth for circuit compatibility

		// 7. Return MerkleProofPath
		Ok(MerkleProofPath::new(path, leaf_index, tree_depth))
	}

	/// Collects sibling path for a **Sparse Merkle Tree**.
	///
	/// # Sparse MT Algorithm
	/// - Always returns exactly `MAX_DEPTH=20` elements
	/// - Uses real siblings when `leaf_index < level_size`
	/// - Uses zero hashes for empty levels
	///
	/// # Parameters
	/// - `block_hash`: Block hash used for queries
	/// - `leaf_index`: Leaf index (0-indexed)
	///
	/// # Returns
	/// - `Vec<Commitment>`: Path with exactly 20 elements
	fn collect_sibling_path(
		&self,
		block_hash: crate::orbinum::domain::BlockHash,
		mut leaf_index: u32,
	) -> ApplicationResult<Vec<Commitment>> {
		const MAX_DEPTH: usize = 20; // Hardcoded in circuits

		// Get tree size
		let tree_size = self.query.get_tree_size(block_hash)?;
		let tree_size_value = tree_size.value();

		log::debug!(
			"🌳 Collecting SPARSE Merkle path: leaf_index={leaf_index}, tree_size={tree_size_value}"
		);

		let mut path = Vec::with_capacity(MAX_DEPTH);

		for level in 0..MAX_DEPTH {
			// Compute this level size (ceil(tree_size / 2^level))
			let level_size = (tree_size_value + (1 << level) - 1) >> level;

			// Decide whether to use storage or zero hash
			// Bug fix: `leaf_index=0` needed a special case
			let should_use_storage = if leaf_index == 0 && level == 0 {
				// Leaf 0, level 0: use storage only if at least 2 leaves exist
				tree_size_value > 1
			} else if leaf_index > 0 {
				// Other indices: use storage when within range
				leaf_index < level_size
			} else {
				// `leaf_index == 0` at upper levels: use zero hash
				false
			};

			if should_use_storage {
				// This level has real data - read sibling from storage
				let sibling_index = leaf_index ^ 1;

				log::debug!(
					"  [{level}] leaf_idx={leaf_index}, sibling_idx={sibling_index} → STORAGE"
				);

				let sibling_hash = self.query.get_leaf(block_hash, sibling_index)?;
				path.push(sibling_hash);

				leaf_index /= 2;
			} else {
				// This level is empty - use zero hash
				log::debug!("  [{level}] leaf_idx={leaf_index} → ZERO_HASH");

				// Use pallet-provided zero hash (Poseidon)
				let zero_hash = get_zero_hash_cached(level);
				path.push(Commitment::new(zero_hash));

				if leaf_index > 0 {
					leaf_index /= 2;
				}
			}
		}

		log::debug!("✅ Sparse path generated: {} elements", path.len());

		Ok(path)
	}

	/// Returns tree information (`root`, `size`, `depth`).
	///
	/// Useful for debugging and validation.
	pub fn get_tree_info(&self) -> ApplicationResult<(Commitment, TreeSize, TreeDepth)> {
		let block_hash = self.query.best_hash()?;
		let root = self.query.get_merkle_root(block_hash)?;
		let size = self.query.get_tree_size(block_hash)?;
		let depth = TreeDepth::from_tree_size(size.value());

		Ok((root, size, depth))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::{BlockHash, DomainError, DomainResult};

	#[derive(Clone, Copy)]
	struct MockQuery {
		root: Commitment,
		tree_size: u32,
		sibling: Commitment,
	}

	impl BlockchainQuery for MockQuery {
		fn best_hash(&self) -> DomainResult<BlockHash> {
			Ok(BlockHash::new([9u8; 32]))
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

		fn get_leaf(&self, _block_hash: BlockHash, leaf_index: u32) -> DomainResult<Commitment> {
			if leaf_index == 1 {
				Ok(self.sibling)
			} else {
				Err(DomainError::LeafIndexOutOfBounds {
					index: leaf_index,
					tree_size: self.tree_size,
				})
			}
		}
	}

	#[test]
	fn should_return_tree_not_initialized_when_tree_is_empty() {
		let query = MockQuery {
			root: Commitment::new([1u8; 32]),
			tree_size: 0,
			sibling: Commitment::new([2u8; 32]),
		};
		let service = MerkleProofService::new(query);

		let result = service.generate_proof(0);

		assert!(matches!(result, Err(ApplicationError::TreeNotInitialized)));
	}

	#[test]
	fn should_return_invalid_leaf_index_when_out_of_bounds() {
		let query = MockQuery {
			root: Commitment::new([1u8; 32]),
			tree_size: 1,
			sibling: Commitment::new([2u8; 32]),
		};
		let service = MerkleProofService::new(query);

		let result = service.generate_proof(1);

		assert!(matches!(
			result,
			Err(ApplicationError::InvalidLeafIndex {
				index: 1,
				tree_size: 1
			})
		));
	}

	#[test]
	fn should_generate_sparse_path_with_fixed_depth() {
		let sibling = Commitment::new([7u8; 32]);
		let query = MockQuery {
			root: Commitment::new([1u8; 32]),
			tree_size: 2,
			sibling,
		};
		let service = MerkleProofService::new(query);

		let proof = service
			.generate_proof(0)
			.expect("proof generation must succeed");

		assert_eq!(proof.leaf_index(), 0);
		assert_eq!(proof.tree_depth().value(), 20);
		assert_eq!(proof.path().len(), 20);
		assert_eq!(proof.path()[0], sibling);
	}

	#[test]
	fn should_return_tree_info() {
		let query = MockQuery {
			root: Commitment::new([3u8; 32]),
			tree_size: 5,
			sibling: Commitment::new([7u8; 32]),
		};
		let service = MerkleProofService::new(query);

		let (root, size, depth) = service.get_tree_info().expect("tree info must succeed");

		assert_eq!(root, Commitment::new([3u8; 32]));
		assert_eq!(size.value(), 5);
		assert_eq!(depth.value(), TreeDepth::from_tree_size(5).value());
	}
}
