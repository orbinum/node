//! Merkle Repository Port - Storage abstraction for Merkle tree operations

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
/// This trait defines the contract that infrastructure adapters must implement
/// to provide Merkle tree persistence. The domain layer depends only on this
/// abstraction, not on concrete implementations.
///
/// ## Domain Invariants
/// - Commitments are inserted in sequential order
/// - Each commitment receives a unique leaf index
/// - The Merkle root must always be computable
/// - Merkle paths must be verifiable
///
/// ## Implementation Notes
/// - Implementations should be thread-safe if used in concurrent contexts
/// - Insertions should be atomic (all-or-nothing)
/// - Retrieval operations should be efficient (O(log n) for proofs)
pub trait MerkleRepository {
	/// Insert a new commitment into the Merkle tree
	///
	/// The commitment is appended as a new leaf, and the repository
	/// returns its index in the tree.
	///
	/// # Domain Logic
	/// - Commitment is added as the next available leaf
	/// - Tree is recomputed to include the new leaf
	/// - Returns the leaf index for later reference
	///
	/// # Arguments
	/// - `commitment`: The commitment to insert
	///
	/// # Returns
	/// - `Ok(leaf_index)`: The index where the commitment was inserted
	/// - `Err(RepositoryError)`: If insertion fails
	///
	/// # Examples
	/// ```ignore
	/// let commitment = Commitment::from(Fr::from(123u64));
	/// let index = repo.insert_commitment(commitment)?;
	/// ```
	fn insert_commitment(&mut self, commitment: Commitment) -> RepositoryResult<u64>;

	/// Get the current Merkle root
	///
	/// The root represents the entire tree state and changes with each insertion.
	///
	/// # Domain Logic
	/// - Returns the hash at the root of the Merkle tree
	/// - If tree is empty, may return a default root or error
	///
	/// # Returns
	/// - `Ok(root)`: The current Merkle root
	/// - `Err(TreeEmpty)`: If the tree has no commitments
	///
	/// # Examples
	/// ```ignore
	/// let root = repo.get_root()?;
	/// ```
	fn get_root(&self) -> RepositoryResult<FieldElement>;

	/// Get a Merkle proof for a specific leaf
	///
	/// The proof contains the sibling hashes needed to verify that
	/// a commitment is included in the tree.
	///
	/// # Domain Logic
	/// - Returns the path from the leaf to the root
	/// - Includes all sibling hashes needed for verification
	/// - Used to prove membership without revealing other leaves
	///
	/// # Arguments
	/// - `leaf_index`: The index of the leaf to prove
	///
	/// # Returns
	/// - `Ok(MerklePath)`: The proof path with siblings
	/// - `Err(LeafNotFound)`: If the index is out of bounds
	///
	/// # Examples
	/// ```ignore
	/// let proof = repo.get_proof(5)?;
	/// assert!(merkle_service.verify_proof(&commitment, &proof, &root));
	/// ```
	fn get_proof(&self, leaf_index: u64) -> RepositoryResult<MerklePath>;

	/// Get the total number of leaves in the tree
	///
	/// This represents the size of the tree (number of commitments).
	///
	/// # Returns
	/// The number of leaves (commitments) in the tree
	fn size(&self) -> u64;

	/// Get a commitment by its leaf index
	///
	/// # Arguments
	/// - `leaf_index`: The index of the leaf to retrieve
	///
	/// # Returns
	/// - `Ok(Commitment)`: The commitment at the given index
	/// - `Err(LeafNotFound)`: If the index is out of bounds
	fn get_commitment(&self, leaf_index: u64) -> RepositoryResult<Commitment>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_merkle_path_creation() {
		let siblings = vec![
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
		];
		let path = MerklePath::new(5, siblings.clone());

		assert_eq!(path.leaf_index, 5);
		assert_eq!(path.siblings, siblings);
		assert_eq!(path.depth(), 3);
		assert!(!path.is_empty());
	}

	#[test]
	fn test_merkle_path_empty() {
		let path = MerklePath::new(0, vec![]);

		assert!(path.is_empty());
		assert_eq!(path.depth(), 0);
	}

	#[test]
	fn test_repository_error_display() {
		let err1 = RepositoryError::LeafNotFound(42);
		assert_eq!(format!("{err1}"), "Leaf not found at index: 42");

		let err2 = RepositoryError::TreeEmpty;
		assert_eq!(format!("{err2}"), "Merkle tree is empty");

		let err3 = RepositoryError::StorageError("disk full".to_string());
		assert_eq!(format!("{err3}"), "Storage error: disk full");
	}

	#[test]
	fn test_repository_error_equality() {
		let err1 = RepositoryError::LeafNotFound(10);
		let err2 = RepositoryError::LeafNotFound(10);
		let err3 = RepositoryError::LeafNotFound(20);

		assert_eq!(err1, err2);
		assert_ne!(err1, err3);
	}
}
