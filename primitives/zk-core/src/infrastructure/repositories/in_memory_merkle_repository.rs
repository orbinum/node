//! In-Memory Merkle Repository - Infrastructure Implementation
//!
//! Concrete implementation of `MerkleRepository` using in-memory storage.
//! Suitable for testing and lightweight applications.

use crate::domain::{
	repositories::{MerklePath, MerkleRepository, RepositoryError},
	value_objects::{Commitment, FieldElement},
};
use alloc::collections::BTreeMap;

/// In-memory Merkle tree repository
///
/// Stores commitments in BTreeMap indexed by position.
#[derive(Debug, Clone, Default)]
pub struct InMemoryMerkleRepository {
	/// Leaves indexed by position
	leaves: BTreeMap<u64, FieldElement>,
	/// Current tree size
	size: u64,
}

impl InMemoryMerkleRepository {
	/// Create a new empty repository
	pub fn new() -> Self {
		Self {
			leaves: BTreeMap::new(),
			size: 0,
		}
	}

	/// Get current tree size
	pub fn size(&self) -> u64 {
		self.size
	}

	/// Clear all leaves
	pub fn clear(&mut self) {
		self.leaves.clear();
		self.size = 0;
	}
}

impl MerkleRepository for InMemoryMerkleRepository {
	fn insert_commitment(&mut self, commitment: Commitment) -> Result<u64, RepositoryError> {
		let position = self.size;
		self.leaves.insert(position, commitment.inner());
		self.size += 1;
		Ok(position)
	}

	fn get_root(&self) -> Result<FieldElement, RepositoryError> {
		if self.size == 0 {
			return Err(RepositoryError::TreeEmpty);
		}

		// For in-memory simple implementation, return last leaf as root
		// In a real Merkle tree, this would compute the full tree root
		self.leaves
			.get(&(self.size - 1))
			.copied()
			.ok_or(RepositoryError::TreeEmpty)
	}

	fn get_proof(&self, leaf_index: u64) -> Result<MerklePath, RepositoryError> {
		if leaf_index >= self.size {
			return Err(RepositoryError::LeafNotFound(leaf_index));
		}

		// For in-memory simple implementation, return empty siblings
		// In a real Merkle tree, this would compute the actual path
		Ok(MerklePath::new(leaf_index, alloc::vec::Vec::new()))
	}

	fn size(&self) -> u64 {
		self.size
	}

	fn get_commitment(&self, leaf_index: u64) -> Result<Commitment, RepositoryError> {
		self.leaves
			.get(&leaf_index)
			.copied()
			.map(Commitment::new)
			.ok_or(RepositoryError::LeafNotFound(leaf_index))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::format;

	fn create_test_commitment(value: u64) -> Commitment {
		Commitment::new(FieldElement::from_u64(value))
	}

	// ===== Construction Tests =====

	#[test]
	fn test_new_repository() {
		let repo = InMemoryMerkleRepository::new();
		assert_eq!(repo.size(), 0);
	}

	#[test]
	fn test_default_trait() {
		let repo = InMemoryMerkleRepository::default();
		assert_eq!(repo.size(), 0);
	}

	#[test]
	fn test_clone() {
		let mut repo1 = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(42);
		repo1.insert_commitment(commitment).unwrap();

		let repo2 = repo1.clone();
		assert_eq!(repo2.size(), repo1.size());
		assert_eq!(
			repo2.get_commitment(0).unwrap(),
			repo1.get_commitment(0).unwrap()
		);
	}

	#[test]
	fn test_clear() {
		let mut repo = InMemoryMerkleRepository::new();
		for i in 0..5 {
			repo.insert_commitment(create_test_commitment(i)).unwrap();
		}
		assert_eq!(repo.size(), 5);

		repo.clear();
		assert_eq!(repo.size(), 0);
		assert!(repo.get_commitment(0).is_err());
	}

	// ===== Insert Tests =====

	#[test]
	fn test_insert_single_commitment() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(42);
		let index = repo.insert_commitment(commitment).unwrap();
		assert_eq!(index, 0);
		assert_eq!(repo.size(), 1);
	}

	#[test]
	fn test_insert_and_get_commitment() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(42);

		let index = repo.insert_commitment(commitment).unwrap();
		assert_eq!(index, 0);
		assert_eq!(repo.size(), 1);

		let retrieved = repo.get_commitment(0).unwrap();
		assert_eq!(retrieved, commitment);
	}

	#[test]
	fn test_insert_multiple_commitments() {
		let mut repo = InMemoryMerkleRepository::new();

		for i in 0..5 {
			let commitment = create_test_commitment(i);
			let index = repo.insert_commitment(commitment).unwrap();
			assert_eq!(index, i);
		}

		assert_eq!(repo.size(), 5);

		// Verify all commitments
		for i in 0..5 {
			let expected = create_test_commitment(i);
			let retrieved = repo.get_commitment(i).unwrap();
			assert_eq!(retrieved, expected);
		}
	}

	#[test]
	fn test_sequential_inserts() {
		let mut repo = InMemoryMerkleRepository::new();

		for i in 0..10 {
			let commitment = create_test_commitment(i * 100);
			let index = repo.insert_commitment(commitment).unwrap();
			assert_eq!(index, i);
			assert_eq!(repo.size(), i + 1);
		}
	}

	#[test]
	fn test_insert_zero_commitment() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(0);
		let index = repo.insert_commitment(commitment).unwrap();
		assert_eq!(index, 0);
	}

	#[test]
	fn test_insert_large_value_commitment() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(u64::MAX);
		let index = repo.insert_commitment(commitment).unwrap();
		assert_eq!(index, 0);
		assert_eq!(repo.get_commitment(0).unwrap(), commitment);
	}

	#[test]
	fn test_insert_duplicate_commitments() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(42);

		let index1 = repo.insert_commitment(commitment).unwrap();
		let index2 = repo.insert_commitment(commitment).unwrap();

		assert_eq!(index1, 0);
		assert_eq!(index2, 1);
		assert_eq!(repo.size(), 2);
	}

	// ===== Get Commitment Tests =====

	#[test]
	fn test_get_commitment_first() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(100);
		repo.insert_commitment(commitment).unwrap();

		let retrieved = repo.get_commitment(0).unwrap();
		assert_eq!(retrieved, commitment);
	}

	#[test]
	fn test_get_commitment_last() {
		let mut repo = InMemoryMerkleRepository::new();
		for i in 0..5 {
			repo.insert_commitment(create_test_commitment(i)).unwrap();
		}

		let last = repo.get_commitment(4).unwrap();
		assert_eq!(last, create_test_commitment(4));
	}

	#[test]
	fn test_get_commitment_middle() {
		let mut repo = InMemoryMerkleRepository::new();
		for i in 0..5 {
			repo.insert_commitment(create_test_commitment(i * 10))
				.unwrap();
		}

		let middle = repo.get_commitment(2).unwrap();
		assert_eq!(middle, create_test_commitment(20));
	}

	#[test]
	fn test_get_commitment_not_found() {
		let repo = InMemoryMerkleRepository::new();
		let result = repo.get_commitment(0);
		assert!(result.is_err());
		assert!(matches!(result, Err(RepositoryError::LeafNotFound(0))));
	}

	#[test]
	fn test_get_commitment_out_of_bounds() {
		let mut repo = InMemoryMerkleRepository::new();
		repo.insert_commitment(create_test_commitment(42)).unwrap();

		let result = repo.get_commitment(5);
		assert!(result.is_err());
		assert!(matches!(result, Err(RepositoryError::LeafNotFound(5))));
	}

	// ===== Get Root Tests =====

	#[test]
	fn test_get_root_empty_tree() {
		let repo = InMemoryMerkleRepository::new();
		let result = repo.get_root();
		assert!(result.is_err());
		assert!(matches!(result, Err(RepositoryError::TreeEmpty)));
	}

	#[test]
	fn test_get_root_single_commitment() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(42);
		repo.insert_commitment(commitment).unwrap();

		let root = repo.get_root().unwrap();
		assert!(!root.is_zero());
	}

	#[test]
	fn test_get_root_with_commitments() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(42);

		repo.insert_commitment(commitment).unwrap();

		let root = repo.get_root();
		assert!(root.is_ok());
		assert!(!root.unwrap().is_zero());
	}

	#[test]
	fn test_get_root_multiple_commitments() {
		let mut repo = InMemoryMerkleRepository::new();
		for i in 0..5 {
			repo.insert_commitment(create_test_commitment(i)).unwrap();
		}

		let root = repo.get_root().unwrap();
		assert!(!root.is_zero());
	}

	#[test]
	fn test_get_root_changes_after_insert() {
		let mut repo = InMemoryMerkleRepository::new();
		repo.insert_commitment(create_test_commitment(1)).unwrap();
		let root1 = repo.get_root().unwrap();

		repo.insert_commitment(create_test_commitment(2)).unwrap();
		let root2 = repo.get_root().unwrap();

		assert_ne!(root1, root2);
	}

	// ===== Get Proof Tests =====

	#[test]
	fn test_get_proof_single_leaf() {
		let mut repo = InMemoryMerkleRepository::new();
		repo.insert_commitment(create_test_commitment(42)).unwrap();

		let proof = repo.get_proof(0).unwrap();
		assert_eq!(proof.leaf_index, 0);
	}

	#[test]
	fn test_get_proof() {
		let mut repo = InMemoryMerkleRepository::new();

		// Insert commitments
		for i in 0..3 {
			let commitment = create_test_commitment(i);
			repo.insert_commitment(commitment).unwrap();
		}

		// Get proof for leaf 1
		let proof = repo.get_proof(1).unwrap();
		assert_eq!(proof.leaf_index, 1);
	}

	#[test]
	fn test_get_proof_first_leaf() {
		let mut repo = InMemoryMerkleRepository::new();
		for i in 0..5 {
			repo.insert_commitment(create_test_commitment(i)).unwrap();
		}

		let proof = repo.get_proof(0).unwrap();
		assert_eq!(proof.leaf_index, 0);
	}

	#[test]
	fn test_get_proof_last_leaf() {
		let mut repo = InMemoryMerkleRepository::new();
		for i in 0..5 {
			repo.insert_commitment(create_test_commitment(i)).unwrap();
		}

		let proof = repo.get_proof(4).unwrap();
		assert_eq!(proof.leaf_index, 4);
	}

	#[test]
	fn test_get_proof_not_found() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(42);
		repo.insert_commitment(commitment).unwrap();

		let result = repo.get_proof(5);
		assert!(result.is_err());
		assert!(matches!(result, Err(RepositoryError::LeafNotFound(5))));
	}

	#[test]
	fn test_get_proof_empty_tree() {
		let repo = InMemoryMerkleRepository::new();
		let result = repo.get_proof(0);
		assert!(result.is_err());
		assert!(matches!(result, Err(RepositoryError::LeafNotFound(0))));
	}

	// ===== Size Tests =====

	#[test]
	fn test_size_empty() {
		let repo = InMemoryMerkleRepository::new();
		assert_eq!(repo.size(), 0);
	}

	#[test]
	fn test_size_after_inserts() {
		let mut repo = InMemoryMerkleRepository::new();
		assert_eq!(repo.size(), 0);

		repo.insert_commitment(create_test_commitment(1)).unwrap();
		assert_eq!(repo.size(), 1);

		repo.insert_commitment(create_test_commitment(2)).unwrap();
		assert_eq!(repo.size(), 2);
	}

	#[test]
	fn test_size_trait_method() {
		let mut repo = InMemoryMerkleRepository::new();
		assert_eq!(repo.size(), 0);

		repo.insert_commitment(create_test_commitment(42)).unwrap();

		let repo_trait: &dyn MerkleRepository = &repo;
		assert_eq!(repo_trait.size(), 1);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_full_workflow() {
		let mut repo = InMemoryMerkleRepository::new();

		// Insert commitments
		for i in 0..5 {
			let commitment = create_test_commitment(i * 100);
			let index = repo.insert_commitment(commitment).unwrap();
			assert_eq!(index, i);
		}

		// Verify size
		assert_eq!(repo.size(), 5);

		// Get root
		let root = repo.get_root().unwrap();
		assert!(!root.is_zero());

		// Get proofs
		for i in 0..5 {
			let proof = repo.get_proof(i).unwrap();
			assert_eq!(proof.leaf_index, i);
		}

		// Get commitments
		for i in 0..5 {
			let commitment = repo.get_commitment(i).unwrap();
			assert_eq!(commitment, create_test_commitment(i * 100));
		}
	}

	#[test]
	fn test_clear_and_reuse() {
		let mut repo = InMemoryMerkleRepository::new();

		// First batch
		for i in 0..3 {
			repo.insert_commitment(create_test_commitment(i)).unwrap();
		}
		assert_eq!(repo.size(), 3);

		// Clear
		repo.clear();
		assert_eq!(repo.size(), 0);

		// Second batch
		for i in 10..13 {
			let index = repo.insert_commitment(create_test_commitment(i)).unwrap();
			assert_eq!(index, i - 10);
		}
		assert_eq!(repo.size(), 3);
	}

	// ===== Trait Implementation Tests =====

	#[test]
	fn test_merkle_repository_trait() {
		let mut repo = InMemoryMerkleRepository::new();
		let repo_trait: &mut dyn MerkleRepository = &mut repo;

		let commitment = create_test_commitment(42);
		let index = repo_trait.insert_commitment(commitment).unwrap();
		assert_eq!(index, 0);

		let retrieved = repo_trait.get_commitment(0).unwrap();
		assert_eq!(retrieved, commitment);
	}

	#[test]
	fn test_debug_format() {
		let repo = InMemoryMerkleRepository::new();
		let debug_str = format!("{repo:?}");
		assert!(debug_str.contains("InMemoryMerkleRepository"));
	}

	// ===== Edge Case Tests =====

	#[test]
	fn test_large_tree() {
		let mut repo = InMemoryMerkleRepository::new();
		let count = 100;

		for i in 0..count {
			let commitment = create_test_commitment(i);
			let index = repo.insert_commitment(commitment).unwrap();
			assert_eq!(index, i);
		}

		assert_eq!(repo.size(), count);

		// Verify all commitments
		for i in 0..count {
			let commitment = repo.get_commitment(i).unwrap();
			assert_eq!(commitment, create_test_commitment(i));
		}
	}
}
