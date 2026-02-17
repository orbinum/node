//! MerkleProofPath entity - Merkle proof path

use crate::orbinum::domain::{Commitment, TreeDepth};

/// Merkle proof path (sibling hashes from leaf to root).
///
/// This entity represents a Merkle verification path that proves
/// a leaf (`commitment`) belongs to a tree.
///
/// # Structure
/// - `path`: Vector of sibling hashes at each level
/// - `leaf_index`: Original leaf index (0-indexed)
/// - `tree_depth`: Tree depth
///
/// # Verification algorithm
/// ```text
/// root = leaf_hash
/// for (i, sibling) in path.iter().enumerate() {
///     if (leaf_index >> i) & 1 == 0 {
///         root = Hash(root, sibling)  // leaf is left child
///     } else {
///         root = Hash(sibling, root)  // leaf is right child
///     }
/// }
/// assert!(root == merkle_root)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProofPath {
	/// Sibling hashes from leaf to root.
	path: Vec<Commitment>,
	/// Leaf index (0-indexed).
	leaf_index: u32,
	/// Tree depth.
	tree_depth: TreeDepth,
}

impl MerkleProofPath {
	/// Creates a new `MerkleProofPath`.
	///
	/// # Parameters
	/// - `path`: Vector of sibling hashes
	/// - `leaf_index`: Leaf index
	/// - `tree_depth`: Tree depth
	pub fn new(path: Vec<Commitment>, leaf_index: u32, tree_depth: TreeDepth) -> Self {
		Self {
			path,
			leaf_index,
			tree_depth,
		}
	}

	/// Returns the sibling path.
	pub fn path(&self) -> &[Commitment] {
		&self.path
	}

	/// Returns the leaf index.
	pub fn leaf_index(&self) -> u32 {
		self.leaf_index
	}

	/// Returns the tree depth.
	pub fn tree_depth(&self) -> TreeDepth {
		self.tree_depth
	}

	/// Checks whether the path is valid (`len(path) <= tree_depth`).
	pub fn is_valid(&self) -> bool {
		self.path.len() <= self.tree_depth.value() as usize
	}

	/// Consumes `self` and returns all components.
	pub fn into_parts(self) -> (Vec<Commitment>, u32, TreeDepth) {
		(self.path, self.leaf_index, self.tree_depth)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_and_read_merkle_proof_path() {
		let path = vec![Commitment::new([1u8; 32]), Commitment::new([2u8; 32])];
		let leaf_index = 7;
		let tree_depth = TreeDepth::new(20);
		let proof = MerkleProofPath::new(path.clone(), leaf_index, tree_depth);

		assert_eq!(proof.path(), path.as_slice());
		assert_eq!(proof.leaf_index(), leaf_index);
		assert_eq!(proof.tree_depth(), tree_depth);
	}

	#[test]
	fn should_validate_path_length_against_tree_depth() {
		let valid = MerkleProofPath::new(
			vec![Commitment::new([1u8; 32]), Commitment::new([2u8; 32])],
			0,
			TreeDepth::new(2),
		);
		let invalid = MerkleProofPath::new(
			vec![
				Commitment::new([1u8; 32]),
				Commitment::new([2u8; 32]),
				Commitment::new([3u8; 32]),
			],
			0,
			TreeDepth::new(2),
		);

		assert!(valid.is_valid());
		assert!(!invalid.is_valid());
	}

	#[test]
	fn should_split_into_parts() {
		let path = vec![Commitment::new([9u8; 32])];
		let proof = MerkleProofPath::new(path.clone(), 3, TreeDepth::new(4));

		let (out_path, out_index, out_depth) = proof.into_parts();

		assert_eq!(out_path, path);
		assert_eq!(out_index, 3);
		assert_eq!(out_depth, TreeDepth::new(4));
	}
}
