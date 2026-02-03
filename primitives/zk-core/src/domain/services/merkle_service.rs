//! # Merkle Service
//!
//! Domain service for Merkle tree operations.
//!

//! Encapsulates the business logic for verifying note membership
//! in the Merkle tree without revealing which note.

use crate::domain::ports::PoseidonHasher;
use crate::domain::value_objects::{Commitment, FieldElement};

/// Domain service for Merkle tree operations
///
/// ## Domain Logic
/// Merkle trees provide:
/// - **Privacy**: Prove note existence without revealing which note
/// - **Efficiency**: Constant-size proofs regardless of tree size
/// - **Immutability**: Once committed, the tree structure cannot change
///
/// ## Tree Structure
/// - Binary tree with commitments as leaves
/// - Internal nodes: hash of left and right children
/// - Root: represents the entire set of commitments
pub struct MerkleService<H: PoseidonHasher> {
	hasher: H,
}

impl<H: PoseidonHasher> MerkleService<H> {
	/// Create a new Merkle service with the given hasher
	pub fn new(hasher: H) -> Self {
		Self { hasher }
	}

	/// Compute the Merkle root from a leaf and its siblings
	///
	/// # Arguments
	/// - `leaf`: The commitment (leaf value)
	/// - `path_elements`: Sibling hashes from leaf to root
	/// - `path_indices`: Bit vector indicating left (0) or right (1) at each level
	///
	/// # Returns
	/// The computed Merkle root
	///
	/// # Privacy
	/// The path elements and indices reveal the position in the tree,
	/// but in ZK circuits this information is kept private.
	pub fn compute_root(
		&self,
		leaf: &Commitment,
		path_elements: &[FieldElement],
		path_indices: &[bool],
	) -> FieldElement {
		let mut current = leaf.inner();

		for (sibling, is_right) in path_elements.iter().zip(path_indices.iter()) {
			let inputs = if *is_right {
				[*sibling, current] // current is on the right
			} else {
				[current, *sibling] // current is on the left
			};

			current = self.hasher.hash_2(inputs);
		}

		current
	}

	/// Verify a Merkle proof
	///
	/// # Arguments
	/// - `leaf`: The commitment to verify
	/// - `path_elements`: Sibling hashes
	/// - `path_indices`: Path positions
	/// - `expected_root`: The expected Merkle root
	///
	/// # Returns
	/// `true` if the proof is valid, `false` otherwise
	pub fn verify_proof(
		&self,
		leaf: &Commitment,
		path_elements: &[FieldElement],
		path_indices: &[bool],
		expected_root: &FieldElement,
	) -> bool {
		let computed_root = self.compute_root(leaf, path_elements, path_indices);
		computed_root == *expected_root
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::Fr;

	// Mock hasher for testing
	struct MockHasher;

	impl PoseidonHasher for MockHasher {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	#[test]
	fn test_compute_root_empty_path() {
		let hasher = MockHasher;
		let service = MerkleService::new(hasher);

		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![];
		let path_indices = vec![];

		let root = service.compute_root(&leaf, &path_elements, &path_indices);

		// Empty path returns the leaf itself
		assert_eq!(root, leaf.inner());
	}

	#[test]
	fn test_compute_root_with_siblings() {
		let hasher = MockHasher;
		let service = MerkleService::new(hasher);

		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200), FieldElement::from_u64(300)];
		let path_indices = vec![false, true];

		let root = service.compute_root(&leaf, &path_elements, &path_indices);

		// Root should be deterministic
		let root2 = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, root2);
	}

	#[test]
	fn test_verify_proof_valid() {
		let hasher = MockHasher;
		let service = MerkleService::new(hasher);

		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false];

		let root = service.compute_root(&leaf, &path_elements, &path_indices);

		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &root);
		assert!(is_valid);
	}

	#[test]
	fn test_verify_proof_invalid() {
		let hasher = MockHasher;
		let service = MerkleService::new(hasher);

		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false];

		let wrong_root = FieldElement::from_u64(999);

		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &wrong_root);
		assert!(!is_valid);
	}
}
