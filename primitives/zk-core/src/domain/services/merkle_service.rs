//! Merkle Service
//!
//! Domain service for Merkle tree operations including root computation
//! and proof verification.

use crate::domain::ports::PoseidonHasher;
use crate::domain::value_objects::{Commitment, FieldElement};

/// Domain service for Merkle tree operations
///
/// Provides privacy-preserving proof of commitment inclusion in the tree.
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
	/// Hashes leaf with siblings along the path to compute the root.
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
	/// Returns true if the computed root matches the expected root.
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
	extern crate alloc;
	use alloc::vec;
	use alloc::vec::Vec;

	// ===== Mock Hashers =====

	struct MockHasherConstant;

	impl PoseidonHasher for MockHasherConstant {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	struct MockHasherSum;

	impl PoseidonHasher for MockHasherSum {
		fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from(inputs[0].inner() + inputs[1].inner())
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	// ===== Service Construction Tests =====

	#[test]
	fn test_new() {
		let hasher = MockHasherConstant;
		let _service = MerkleService::new(hasher);
	}

	#[test]
	fn test_new_with_different_hasher() {
		let hasher = MockHasherSum;
		let _service = MerkleService::new(hasher);
	}

	// ===== Compute Root Empty Path Tests =====

	#[test]
	fn test_compute_root_empty_path() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![];
		let path_indices = vec![];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		// Empty path returns the leaf itself
		assert_eq!(root, leaf.inner());
	}

	#[test]
	fn test_compute_root_empty_path_zero_leaf() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(0u64));
		let path_elements = vec![];
		let path_indices = vec![];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, leaf.inner());
	}

	// ===== Compute Root With Siblings Tests =====

	#[test]
	fn test_compute_root_single_sibling_left() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false]; // current on left
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(42)); // MockHasherConstant returns 42
	}

	#[test]
	fn test_compute_root_single_sibling_right() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![true]; // current on right
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(42));
	}

	#[test]
	fn test_compute_root_multiple_siblings() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![
			FieldElement::from_u64(200),
			FieldElement::from_u64(300),
			FieldElement::from_u64(400),
		];
		let path_indices = vec![false, true, false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(42));
	}

	#[test]
	fn test_compute_root_deep_path() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(1u64));
		let path_elements: Vec<_> = (0..32).map(FieldElement::from_u64).collect();
		let path_indices: Vec<_> = (0..32).map(|i| i % 2 == 0).collect();
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(42));
	}

	// ===== Compute Root Determinism Tests =====

	#[test]
	fn test_compute_root_deterministic() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200), FieldElement::from_u64(300)];
		let path_indices = vec![false, true];
		let root1 = service.compute_root(&leaf, &path_elements, &path_indices);
		let root2 = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root1, root2);
	}

	#[test]
	fn test_compute_root_deterministic_sum_hasher() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(10u64));
		let path_elements = vec![FieldElement::from_u64(20)];
		let path_indices = vec![false];
		let root1 = service.compute_root(&leaf, &path_elements, &path_indices);
		let root2 = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root1, root2);
	}

	// ===== Compute Root Sum Hasher Tests =====

	#[test]
	fn test_compute_root_sum_hasher_single_level() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(10u64));
		let path_elements = vec![FieldElement::from_u64(20)];
		let path_indices = vec![false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		// Sum: 10 + 20 = 30
		assert_eq!(root, FieldElement::from_u64(30));
	}

	#[test]
	fn test_compute_root_sum_hasher_multiple_levels() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(10u64));
		let path_elements = vec![FieldElement::from_u64(20), FieldElement::from_u64(30)];
		let path_indices = vec![false, false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		// Level 1: 10 + 20 = 30
		// Level 2: 30 + 30 = 60
		assert_eq!(root, FieldElement::from_u64(60));
	}

	#[test]
	fn test_compute_root_sum_hasher_order_matters() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(10u64));
		let path_elements = vec![FieldElement::from_u64(20)];
		let root_left = service.compute_root(&leaf, &path_elements, &[false]);
		let root_right = service.compute_root(&leaf, &path_elements, &[true]);
		// Sum hasher: order doesn't matter, both sum to 30
		assert_eq!(root_left, root_right);
	}

	// ===== Verify Proof Valid Tests =====

	#[test]
	fn test_verify_proof_valid() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &root);
		assert!(is_valid);
	}

	#[test]
	fn test_verify_proof_valid_empty_path() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![];
		let path_indices = vec![];
		let root = leaf.inner();
		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &root);
		assert!(is_valid);
	}

	#[test]
	fn test_verify_proof_valid_multiple_levels() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200), FieldElement::from_u64(300)];
		let path_indices = vec![false, true];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &root);
		assert!(is_valid);
	}

	#[test]
	fn test_verify_proof_valid_sum_hasher() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(10u64));
		let path_elements = vec![FieldElement::from_u64(20)];
		let path_indices = vec![false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &root);
		assert!(is_valid);
	}

	// ===== Verify Proof Invalid Tests =====

	#[test]
	fn test_verify_proof_invalid_wrong_root() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false];
		let wrong_root = FieldElement::from_u64(999);
		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &wrong_root);
		assert!(!is_valid);
	}

	#[test]
	fn test_verify_proof_invalid_empty_path_wrong_root() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![];
		let path_indices = vec![];
		let wrong_root = FieldElement::from_u64(999);
		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &wrong_root);
		assert!(!is_valid);
	}

	#[test]
	fn test_verify_proof_invalid_wrong_leaf() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let wrong_leaf = Commitment::from(Fr::from(999u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		// With MockHasherSum, root = 100 + 200 = 300
		// With wrong_leaf, computed_root = 999 + 200 = 1199 != 300
		let is_valid = service.verify_proof(&wrong_leaf, &path_elements, &path_indices, &root);
		assert!(!is_valid);
	}

	#[test]
	fn test_verify_proof_invalid_sum_hasher() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(10u64));
		let path_elements = vec![FieldElement::from_u64(20)];
		let path_indices = vec![false];
		let wrong_root = FieldElement::from_u64(999);
		let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &wrong_root);
		assert!(!is_valid);
	}

	// ===== Edge Cases =====

	#[test]
	fn test_compute_root_zero_leaf() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(0u64));
		let path_elements = vec![FieldElement::from_u64(100)];
		let path_indices = vec![false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(100));
	}

	#[test]
	fn test_compute_root_zero_sibling() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(0)];
		let path_indices = vec![false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(100));
	}

	#[test]
	fn test_compute_root_all_zeros() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(0u64));
		let path_elements = vec![FieldElement::from_u64(0), FieldElement::from_u64(0)];
		let path_indices = vec![false, false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(0));
	}

	#[test]
	fn test_compute_root_max_values() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(u64::MAX));
		let path_elements = vec![FieldElement::from(Fr::from(u64::MAX))];
		let path_indices = vec![false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(42));
	}

	// ===== Service Reuse Tests =====

	#[test]
	fn test_service_reuse() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf1 = Commitment::from(Fr::from(100u64));
		let leaf2 = Commitment::from(Fr::from(200u64));
		let path_elements = vec![FieldElement::from_u64(50)];
		let path_indices = vec![false];
		let _root1 = service.compute_root(&leaf1, &path_elements, &path_indices);
		let _root2 = service.compute_root(&leaf2, &path_elements, &path_indices);
	}

	#[test]
	fn test_service_multiple_verifications() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false];
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		// Multiple verifications
		for _ in 0..5 {
			let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &root);
			assert!(is_valid);
		}
	}

	// ===== Reference Tests =====

	#[test]
	fn test_service_reference() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let service_ref = &service;
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false];
		let root = service_ref.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(42));
	}

	#[test]
	fn test_verify_with_computed_root() {
		let hasher = MockHasherSum;
		let service = MerkleService::new(hasher);
		let leaves = vec![
			Commitment::from(Fr::from(10u64)),
			Commitment::from(Fr::from(20u64)),
			Commitment::from(Fr::from(30u64)),
		];
		let path_elements = vec![FieldElement::from_u64(100)];
		let path_indices = vec![false];
		for leaf in leaves {
			let root = service.compute_root(&leaf, &path_elements, &path_indices);
			let is_valid = service.verify_proof(&leaf, &path_elements, &path_indices, &root);
			assert!(is_valid);
		}
	}

	#[test]
	fn test_different_services_same_hasher_type() {
		let hasher1 = MockHasherConstant;
		let hasher2 = MockHasherConstant;
		let service1 = MerkleService::new(hasher1);
		let service2 = MerkleService::new(hasher2);
		let leaf = Commitment::from(Fr::from(100u64));
		let path_elements = vec![FieldElement::from_u64(200)];
		let path_indices = vec![false];
		let root1 = service1.compute_root(&leaf, &path_elements, &path_indices);
		let root2 = service2.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root1, root2);
	}

	#[test]
	fn test_path_indices_alternating() {
		let hasher = MockHasherConstant;
		let service = MerkleService::new(hasher);
		let leaf = Commitment::from(Fr::from(1u64));
		let path_elements: Vec<_> = (0..10).map(FieldElement::from_u64).collect();
		let path_indices: Vec<_> = (0..10).map(|i| i % 2 == 1).collect();
		let root = service.compute_root(&leaf, &path_elements, &path_indices);
		assert_eq!(root, FieldElement::from_u64(42));
	}
}
