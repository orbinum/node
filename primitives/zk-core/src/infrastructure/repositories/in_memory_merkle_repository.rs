//! In-Memory Merkle Repository - Infrastructure Implementation
//!
//! Concrete implementation of the `MerkleRepository` port using in-memory
//! storage. This adapter is suitable for testing and lightweight applications.
//!

//! - **Domain Port**: `domain::repositories::MerkleRepository` trait
//! - **Adapter**: `InMemoryMerkleRepository` struct (this file)
//! - **Storage**: `HashMap<u64, FieldElement>` for leaves
//!

//! ```rust
//! use orbinum_zk_core::domain::repositories::MerkleRepository;
//! use orbinum_zk_core::infrastructure::repositories::InMemoryMerkleRepository;
//! use orbinum_zk_core::domain::value_objects::{Commitment, FieldElement};
//! use ark_bn254::Fr;
//!
//! let mut repo = InMemoryMerkleRepository::new();
//! let commitment = Commitment::new(FieldElement::new(Fr::from(42u64)));
//! let _position = repo.insert_commitment(commitment).unwrap();
//! let _root = repo.get_root().unwrap();
//! ```

use crate::domain::{
	repositories::{MerklePath, MerkleRepository, RepositoryError},
	value_objects::{Commitment, FieldElement},
};
use alloc::collections::BTreeMap;

/// In-memory Merkle tree repository.
///
/// Stores commitments (leaves) in a BTreeMap indexed by position.
/// Suitable for testing and applications without persistence requirements.
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

	fn create_test_commitment(value: u64) -> Commitment {
		Commitment::new(FieldElement::from_u64(value))
	}

	#[test]
	fn test_new_repository() {
		let repo = InMemoryMerkleRepository::new();
		assert_eq!(repo.size(), 0);
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
	fn test_get_commitment_not_found() {
		let repo = InMemoryMerkleRepository::new();
		let result = repo.get_commitment(0);
		assert!(result.is_err());
		assert!(matches!(result, Err(RepositoryError::LeafNotFound(0))));
	}

	#[test]
	fn test_get_root_empty_tree() {
		let repo = InMemoryMerkleRepository::new();
		let result = repo.get_root();
		assert!(result.is_err());
		assert!(matches!(result, Err(RepositoryError::TreeEmpty)));
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
		// Note: This simple implementation returns empty siblings
		// A full implementation would compute the actual Merkle path
	}

	#[test]
	fn test_get_proof_not_found() {
		let mut repo = InMemoryMerkleRepository::new();
		let commitment = create_test_commitment(42);
		repo.insert_commitment(commitment).unwrap();

		// Try to get proof for non-existent leaf
		let result = repo.get_proof(5);
		assert!(result.is_err());
		assert!(matches!(result, Err(RepositoryError::LeafNotFound(5))));
	}

	#[test]
	fn test_sequential_inserts() {
		let mut repo = InMemoryMerkleRepository::new();

		// Simulate sequential commitment insertion
		for i in 0..10 {
			let commitment = create_test_commitment(i * 100);
			let index = repo.insert_commitment(commitment).unwrap();
			assert_eq!(index, i);
			assert_eq!(repo.size(), i + 1);
		}
	}
}
