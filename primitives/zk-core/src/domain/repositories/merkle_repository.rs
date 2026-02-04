//! Merkle Repository Port
//!
//! Storage abstraction defining the interface for Merkle tree operations.

use crate::domain::value_objects::{Commitment, FieldElement};
use alloc::{string::String, vec::Vec};

/// Result type for repository operations
pub type RepositoryResult<T> = Result<T, RepositoryError>;

/// Errors that can occur during repository operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
	/// Leaf index is out of bounds
	LeafNotFound(u64),
	/// Merkle tree is empty
	TreeEmpty,
	/// Internal storage error
	StorageError(String),
}

impl core::fmt::Display for RepositoryError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			RepositoryError::LeafNotFound(index) => {
				write!(f, "Leaf not found at index: {index}")
			}
			RepositoryError::TreeEmpty => write!(f, "Merkle tree is empty"),
			RepositoryError::StorageError(msg) => write!(f, "Storage error: {msg}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for RepositoryError {}

/// Merkle path from a leaf to the root
///
/// Contains the sibling hashes needed to verify a Merkle proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePath {
	/// Leaf index in the tree
	pub leaf_index: u64,
	/// Sibling hashes from leaf to root
	pub siblings: Vec<FieldElement>,
}

impl MerklePath {
	/// Create a new Merkle path
	pub fn new(leaf_index: u64, siblings: Vec<FieldElement>) -> Self {
		Self {
			leaf_index,
			siblings,
		}
	}

	/// Get the depth of the path (number of siblings)
	pub fn depth(&self) -> usize {
		self.siblings.len()
	}

	/// Check if the path is empty (no siblings)
	pub fn is_empty(&self) -> bool {
		self.siblings.is_empty()
	}
}

/// Port (interface) for Merkle tree storage
///
/// Defines the contract for Merkle tree persistence that infrastructure
/// adapters must implement.
pub trait MerkleRepository {
	/// Insert a new commitment into the Merkle tree
	///
	/// Returns the leaf index where the commitment was inserted.
	fn insert_commitment(&mut self, commitment: Commitment) -> RepositoryResult<u64>;

	/// Get the current Merkle root
	///
	/// Returns the hash at the root of the Merkle tree.
	fn get_root(&self) -> RepositoryResult<FieldElement>;

	/// Get a Merkle proof for a specific leaf
	///
	/// Returns the path containing sibling hashes needed to verify
	/// commitment inclusion in the tree.
	fn get_proof(&self, leaf_index: u64) -> RepositoryResult<MerklePath>;

	/// Get the total number of leaves in the tree
	///
	/// Returns the count of commitments in the tree.
	fn size(&self) -> u64;

	/// Get a commitment by its leaf index
	///
	/// Returns the commitment at the specified index.
	fn get_commitment(&self, leaf_index: u64) -> RepositoryResult<Commitment>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::Fr;
	extern crate alloc;
	use alloc::string::ToString;
	use alloc::{format, vec};

	// ===== MerklePath Construction Tests =====

	#[test]
	fn test_merkle_path_new() {
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let path = MerklePath::new(5, siblings.clone());
		assert_eq!(path.leaf_index, 5);
		assert_eq!(path.siblings, siblings);
	}

	#[test]
	fn test_merkle_path_new_empty() {
		let path = MerklePath::new(0, vec![]);
		assert_eq!(path.leaf_index, 0);
		assert!(path.siblings.is_empty());
	}

	#[test]
	fn test_merkle_path_new_single() {
		let siblings = vec![FieldElement::from_u64(42)];
		let path = MerklePath::new(10, siblings.clone());
		assert_eq!(path.leaf_index, 10);
		assert_eq!(path.siblings.len(), 1);
	}

	#[test]
	fn test_merkle_path_new_many() {
		let siblings = vec![
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
			FieldElement::from_u64(5),
		];
		let path = MerklePath::new(100, siblings.clone());
		assert_eq!(path.leaf_index, 100);
		assert_eq!(path.siblings.len(), 5);
	}

	#[test]
	fn test_merkle_path_new_large_index() {
		let path = MerklePath::new(u64::MAX, vec![]);
		assert_eq!(path.leaf_index, u64::MAX);
	}

	// ===== MerklePath Methods Tests =====

	#[test]
	fn test_merkle_path_depth() {
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let path = MerklePath::new(0, siblings);
		assert_eq!(path.depth(), 2);
	}

	#[test]
	fn test_merkle_path_depth_zero() {
		let path = MerklePath::new(0, vec![]);
		assert_eq!(path.depth(), 0);
	}

	#[test]
	fn test_merkle_path_depth_large() {
		let siblings: Vec<FieldElement> = (0..32).map(FieldElement::from_u64).collect();
		let path = MerklePath::new(0, siblings);
		assert_eq!(path.depth(), 32);
	}

	#[test]
	fn test_merkle_path_is_empty_true() {
		let path = MerklePath::new(0, vec![]);
		assert!(path.is_empty());
	}

	#[test]
	fn test_merkle_path_is_empty_false() {
		let siblings = vec![FieldElement::from_u64(1)];
		let path = MerklePath::new(0, siblings);
		assert!(!path.is_empty());
	}

	#[test]
	fn test_merkle_path_is_empty_many() {
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let path = MerklePath::new(0, siblings);
		assert!(!path.is_empty());
	}

	// ===== MerklePath Clone and Equality Tests =====

	#[test]
	fn test_merkle_path_clone() {
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let path1 = MerklePath::new(5, siblings);
		let path2 = path1.clone();
		assert_eq!(path1, path2);
	}

	#[test]
	fn test_merkle_path_partial_eq_equal() {
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let path1 = MerklePath::new(5, siblings.clone());
		let path2 = MerklePath::new(5, siblings);
		assert_eq!(path1, path2);
	}

	#[test]
	fn test_merkle_path_partial_eq_different_index() {
		let siblings = vec![FieldElement::from_u64(1)];
		let path1 = MerklePath::new(5, siblings.clone());
		let path2 = MerklePath::new(10, siblings);
		assert_ne!(path1, path2);
	}

	#[test]
	fn test_merkle_path_partial_eq_different_siblings() {
		let siblings1 = vec![FieldElement::from_u64(1)];
		let siblings2 = vec![FieldElement::from_u64(2)];
		let path1 = MerklePath::new(5, siblings1);
		let path2 = MerklePath::new(5, siblings2);
		assert_ne!(path1, path2);
	}

	#[test]
	fn test_merkle_path_debug() {
		let siblings = vec![FieldElement::from_u64(1)];
		let path = MerklePath::new(5, siblings);
		let debug_str = format!("{path:?}");
		assert!(debug_str.contains("MerklePath"));
	}

	// ===== RepositoryError Tests =====

	#[test]
	fn test_repository_error_leaf_not_found() {
		let err = RepositoryError::LeafNotFound(42);
		assert!(matches!(err, RepositoryError::LeafNotFound(42)));
	}

	#[test]
	fn test_repository_error_tree_empty() {
		let err = RepositoryError::TreeEmpty;
		assert!(matches!(err, RepositoryError::TreeEmpty));
	}

	#[test]
	fn test_repository_error_storage_error() {
		let err = RepositoryError::StorageError("disk full".to_string());
		assert!(matches!(err, RepositoryError::StorageError(_)));
	}

	#[test]
	fn test_repository_error_display_leaf_not_found() {
		let err = RepositoryError::LeafNotFound(42);
		assert_eq!(format!("{err}"), "Leaf not found at index: 42");
	}

	#[test]
	fn test_repository_error_display_tree_empty() {
		let err = RepositoryError::TreeEmpty;
		assert_eq!(format!("{err}"), "Merkle tree is empty");
	}

	#[test]
	fn test_repository_error_display_storage_error() {
		let err = RepositoryError::StorageError("disk full".to_string());
		assert_eq!(format!("{err}"), "Storage error: disk full");
	}

	#[test]
	fn test_repository_error_clone() {
		let err1 = RepositoryError::LeafNotFound(10);
		let err2 = err1.clone();
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_repository_error_partial_eq_same() {
		let err1 = RepositoryError::LeafNotFound(10);
		let err2 = RepositoryError::LeafNotFound(10);
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_repository_error_partial_eq_different_index() {
		let err1 = RepositoryError::LeafNotFound(10);
		let err2 = RepositoryError::LeafNotFound(20);
		assert_ne!(err1, err2);
	}

	#[test]
	fn test_repository_error_partial_eq_different_variants() {
		let err1 = RepositoryError::LeafNotFound(10);
		let err2 = RepositoryError::TreeEmpty;
		assert_ne!(err1, err2);
	}

	#[test]
	fn test_repository_error_partial_eq_storage_same() {
		let err1 = RepositoryError::StorageError("error".to_string());
		let err2 = RepositoryError::StorageError("error".to_string());
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_repository_error_partial_eq_storage_different() {
		let err1 = RepositoryError::StorageError("error1".to_string());
		let err2 = RepositoryError::StorageError("error2".to_string());
		assert_ne!(err1, err2);
	}

	#[test]
	fn test_repository_error_debug() {
		let err = RepositoryError::LeafNotFound(42);
		let debug_str = format!("{err:?}");
		assert!(debug_str.contains("LeafNotFound"));
		assert!(debug_str.contains("42"));
	}

	// ===== Mock Repository for Testing Trait =====

	struct MockRepository {
		commitments: Vec<Commitment>,
	}

	impl MockRepository {
		fn new() -> Self {
			Self {
				commitments: Vec::new(),
			}
		}
	}

	impl MerkleRepository for MockRepository {
		fn insert_commitment(&mut self, commitment: Commitment) -> RepositoryResult<u64> {
			let index = self.commitments.len() as u64;
			self.commitments.push(commitment);
			Ok(index)
		}

		fn get_root(&self) -> RepositoryResult<FieldElement> {
			if self.commitments.is_empty() {
				Err(RepositoryError::TreeEmpty)
			} else {
				Ok(FieldElement::from_u64(42))
			}
		}

		fn get_proof(&self, leaf_index: u64) -> RepositoryResult<MerklePath> {
			if leaf_index >= self.commitments.len() as u64 {
				Err(RepositoryError::LeafNotFound(leaf_index))
			} else {
				Ok(MerklePath::new(leaf_index, vec![]))
			}
		}

		fn size(&self) -> u64 {
			self.commitments.len() as u64
		}

		fn get_commitment(&self, leaf_index: u64) -> RepositoryResult<Commitment> {
			self.commitments
				.get(leaf_index as usize)
				.cloned()
				.ok_or(RepositoryError::LeafNotFound(leaf_index))
		}
	}

	// ===== Trait Implementation Tests =====

	#[test]
	fn test_mock_repository_new() {
		let repo = MockRepository::new();
		assert_eq!(repo.size(), 0);
	}

	#[test]
	fn test_mock_repository_insert() {
		let mut repo = MockRepository::new();
		let commitment = Commitment::from(Fr::from(123u64));
		let result = repo.insert_commitment(commitment);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), 0);
		assert_eq!(repo.size(), 1);
	}

	#[test]
	fn test_mock_repository_insert_multiple() {
		let mut repo = MockRepository::new();
		let commitment1 = Commitment::from(Fr::from(100u64));
		let commitment2 = Commitment::from(Fr::from(200u64));
		let commitment3 = Commitment::from(Fr::from(300u64));
		assert_eq!(repo.insert_commitment(commitment1).unwrap(), 0);
		assert_eq!(repo.insert_commitment(commitment2).unwrap(), 1);
		assert_eq!(repo.insert_commitment(commitment3).unwrap(), 2);
		assert_eq!(repo.size(), 3);
	}

	#[test]
	fn test_mock_repository_get_root_empty() {
		let repo = MockRepository::new();
		let result = repo.get_root();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), RepositoryError::TreeEmpty);
	}

	#[test]
	fn test_mock_repository_get_root_with_commitments() {
		let mut repo = MockRepository::new();
		let commitment = Commitment::from(Fr::from(123u64));
		repo.insert_commitment(commitment).unwrap();
		let result = repo.get_root();
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), FieldElement::from_u64(42));
	}

	#[test]
	fn test_mock_repository_get_proof_valid() {
		let mut repo = MockRepository::new();
		let commitment = Commitment::from(Fr::from(123u64));
		repo.insert_commitment(commitment).unwrap();
		let result = repo.get_proof(0);
		assert!(result.is_ok());
		let path = result.unwrap();
		assert_eq!(path.leaf_index, 0);
	}

	#[test]
	fn test_mock_repository_get_proof_invalid() {
		let mut repo = MockRepository::new();
		let commitment = Commitment::from(Fr::from(123u64));
		repo.insert_commitment(commitment).unwrap();
		let result = repo.get_proof(5);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), RepositoryError::LeafNotFound(5));
	}

	#[test]
	fn test_mock_repository_get_commitment_valid() {
		let mut repo = MockRepository::new();
		let commitment = Commitment::from(Fr::from(123u64));
		repo.insert_commitment(commitment).unwrap();
		let result = repo.get_commitment(0);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), commitment);
	}

	#[test]
	fn test_mock_repository_get_commitment_invalid() {
		let repo = MockRepository::new();
		let result = repo.get_commitment(0);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), RepositoryError::LeafNotFound(0));
	}

	#[test]
	fn test_mock_repository_size_empty() {
		let repo = MockRepository::new();
		assert_eq!(repo.size(), 0);
	}

	#[test]
	fn test_mock_repository_size_with_insertions() {
		let mut repo = MockRepository::new();
		for i in 0..10 {
			let commitment = Commitment::from(Fr::from(i));
			repo.insert_commitment(commitment).unwrap();
		}
		assert_eq!(repo.size(), 10);
	}

	#[test]
	fn test_repository_result_type() {
		let result: RepositoryResult<u64> = Ok(42);
		assert!(result.is_ok());
		if let Ok(value) = result {
			assert_eq!(value, 42);
		}
	}

	#[test]
	fn test_repository_result_error() {
		let result: RepositoryResult<u64> = Err(RepositoryError::TreeEmpty);
		assert!(result.is_err());
	}
}
