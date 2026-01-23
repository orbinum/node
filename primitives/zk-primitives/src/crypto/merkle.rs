//! # Merkle Tree
//!
//! Implements Merkle tree membership proof verification using strong types.
//! This allows proving that a leaf (commitment) exists in a Merkle tree
//! without revealing which leaf it is.
//!
//! ## Architecture
//!
//! The verifier works by:
//! 1. Starting with the leaf (commitment)
//! 2. For each level, computing: `new_hash = Poseidon(left, right)`
//! 3. Path index determines if current is left (0) or right (1)
//! 4. Final hash should equal the known root
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_primitives::crypto::merkle::verify_merkle_proof;
//! use fp_zk_primitives::core::types::{Commitment, MerkleRoot};
//!
//! // Verify a Merkle proof
//! let is_valid = verify_merkle_proof(
//!     &leaf,
//!     &path_elements,
//!     &path_indices,
//!     &expected_root,
//! );
//! ```
//!
//! ## Compatibility
//!
//! This implementation matches the circomlib Merkle tree verifier and uses
//! Poseidon hash for all internal hashing.

use crate::core::constants::MAX_TREE_DEPTH;
use crate::core::types::{Bn254Fr, Commitment, MerkleRoot};
use crate::crypto::hash::poseidon_hash_2;

// ============================================================================
// Merkle Tree Functions
// ============================================================================

/// Computes a Merkle root from a leaf and proof path
///
/// # Arguments
///
/// * `leaf` - The leaf value (commitment) to prove membership
/// * `path_elements` - Sibling hashes along the path
/// * `path_indices` - Direction at each level (false=left, true=right)
///
/// # Returns
///
/// The computed Merkle root
///
/// # Panics
///
/// Panics if path_elements and path_indices have different lengths
pub fn compute_merkle_root(
	leaf: &Commitment,
	path_elements: &[MerkleRoot],
	path_indices: &[bool],
) -> MerkleRoot {
	assert_eq!(
		path_elements.len(),
		path_indices.len(),
		"Path elements and indices must have same length"
	);

	assert!(
		path_elements.len() <= MAX_TREE_DEPTH,
		"Path length exceeds maximum tree depth"
	);

	let mut current = leaf.0;

	for (sibling, &is_right) in path_elements.iter().zip(path_indices.iter()) {
		// If is_right: hash(sibling, current) - current is on the right
		// If !is_right: hash(current, sibling) - current is on the left
		let (left, right) = if is_right {
			(*sibling, current)
		} else {
			(current, *sibling)
		};

		current = poseidon_hash_2(&[left, right]);
	}

	current
}

/// Verifies a Merkle proof
///
/// # Arguments
///
/// * `leaf` - The leaf value to verify
/// * `path_elements` - Sibling hashes along the path
/// * `path_indices` - Direction at each level
/// * `expected_root` - The expected Merkle root
///
/// # Returns
///
/// `true` if the proof is valid, `false` otherwise
pub fn verify_merkle_proof(
	leaf: &Commitment,
	path_elements: &[MerkleRoot],
	path_indices: &[bool],
	expected_root: &MerkleRoot,
) -> bool {
	let computed_root = compute_merkle_root(leaf, path_elements, path_indices);
	computed_root == *expected_root
}

/// Computes an empty tree root for a given depth
///
/// An empty tree has all leaves as zero, so we can precompute the root.
///
/// # Arguments
///
/// * `depth` - The depth of the tree
///
/// # Returns
///
/// The root hash of an empty tree
///
/// # Panics
///
/// Panics if depth exceeds MAX_TREE_DEPTH
pub fn compute_empty_root(depth: usize) -> MerkleRoot {
	assert!(
		depth <= MAX_TREE_DEPTH,
		"Tree depth exceeds maximum allowed depth"
	);

	let mut current = Bn254Fr::from(0u64);

	for _ in 0..depth {
		current = poseidon_hash_2(&[current, current]);
	}

	current
}
