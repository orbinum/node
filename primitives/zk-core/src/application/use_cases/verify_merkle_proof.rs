//! Verify Merkle Proof Use Case
//!
//! This use case encapsulates the business logic for verifying a Merkle proof.
//!

//! This is part of the **Application Layer** (use cases).
//!

//! Coordinate the verification of a Merkle proof using domain services.

use alloc::{string::String, vec::Vec};
use crate::domain::{
	ports::PoseidonHasher,
	services::MerkleService,
	value_objects::{Commitment, FieldElement},
};

/// Input data for verifying a Merkle proof
#[derive(Debug, Clone)]
pub struct VerifyMerkleProofInput {
	/// The commitment (leaf) to verify
	pub commitment: Commitment,
	/// The sibling hashes in the path
	pub siblings: Vec<FieldElement>,
	/// The expected root
	pub root: FieldElement,
}

/// Output data after verifying proof
#[derive(Debug, Clone)]
pub struct VerifyMerkleProofOutput {
	/// Whether the proof is valid
	pub is_valid: bool,
}

/// Result type for the use case
pub type VerifyMerkleProofResult = Result<VerifyMerkleProofOutput, VerifyMerkleProofError>;

/// Errors that can occur when verifying proof
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyMerkleProofError {
	/// Hasher error
	HasherError(String),
	/// Invalid proof structure
	InvalidProof(String),
}

impl core::fmt::Display for VerifyMerkleProofError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			VerifyMerkleProofError::HasherError(msg) => write!(f, "Hasher error: {msg}"),
			VerifyMerkleProofError::InvalidProof(msg) => write!(f, "Invalid proof: {msg}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyMerkleProofError {}

/// Use case for verifying a Merkle proof
///
/// This use case verifies that a commitment is included in a Merkle tree
/// by checking the proof path to the root.
///
/// ## Application Logic Flow
/// 1. Receive commitment, proof path, and expected root
/// 2. Use domain service to verify the proof
/// 3. Return verification result
///
/// ## Example
/// ```ignore
/// let commitment = Commitment::from(Fr::from(123u64));
/// let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
/// let root = FieldElement::from_u64(42);
/// let hasher = PoseidonHasherImpl;
///
/// let input = VerifyMerkleProofInput { commitment, siblings, root };
/// let use_case = VerifyMerkleProofUseCase;
/// let output = use_case.execute(input, hasher)?;
/// ```
pub struct VerifyMerkleProofUseCase;

impl VerifyMerkleProofUseCase {
	/// Create a new instance of the use case
	pub fn new() -> Self {
		Self
	}

	/// Execute the use case
	///
	/// # Arguments
	/// - `input`: The input data containing commitment, proof path, and root
	/// - `hasher`: Implementation of PoseidonHasher port
	///
	/// # Returns
	/// - `Ok(VerifyMerkleProofOutput)`: The verification result
	/// - `Err(VerifyMerkleProofError)`: If verification fails
	pub fn execute<H: PoseidonHasher>(
		&self,
		input: VerifyMerkleProofInput,
		hasher: H,
	) -> VerifyMerkleProofResult {
		// Create domain service
		let service = MerkleService::new(hasher);

		// Convert siblings to non-empty slice or use empty slice
		let siblings_slice: &[FieldElement] = &input.siblings;

		// Delegate to domain service
		let is_valid = service.verify_proof(&input.commitment, siblings_slice, &[], &input.root);

		Ok(VerifyMerkleProofOutput { is_valid })
	}
}

impl Default for VerifyMerkleProofUseCase {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::Fr;

	struct MockHasher;

	impl PoseidonHasher for MockHasher {
		fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
			// Simple deterministic mock: just return first input
			// This makes verify_proof trivial but testable
			inputs[0]
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	#[test]
	fn test_verify_proof_valid() {
		let use_case = VerifyMerkleProofUseCase::new();

		// With our mock hasher that returns first input:
		// compute_root will just return the leaf
		// So root should equal leaf for valid proof
		let leaf_value = Fr::from(42u64);
		let leaf = Commitment::from(leaf_value);
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let root = FieldElement::from(leaf_value); // Root = leaf in this mock

		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};

		let hasher = MockHasher;
		let result = use_case.execute(input, hasher);

		assert!(result.is_ok());
		let output = result.unwrap();
		assert!(output.is_valid);
	}

	#[test]
	fn test_verify_proof_invalid() {
		let use_case = VerifyMerkleProofUseCase::new();

		let leaf = Commitment::from(Fr::from(10u64));
		let siblings = vec![FieldElement::from_u64(5)];
		// Wrong root (should be 15 but we use 20)
		let root = FieldElement::from_u64(20);

		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};

		let hasher = MockHasher;
		let result = use_case.execute(input, hasher);

		assert!(result.is_ok());
		let output = result.unwrap();
		assert!(!output.is_valid);
	}

	#[test]
	fn test_verify_proof_empty_path() {
		let use_case = VerifyMerkleProofUseCase::new();

		let leaf = Commitment::from(Fr::from(42u64));
		let siblings = vec![];
		let root = FieldElement::from_u64(42);

		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};

		let hasher = MockHasher;
		let result = use_case.execute(input, hasher);

		assert!(result.is_ok());
		let output = result.unwrap();
		assert!(output.is_valid);
	}

	#[test]
	fn test_error_display() {
		let err1 = VerifyMerkleProofError::HasherError("hash computation failed".to_string());
		assert_eq!(format!("{err1}"), "Hasher error: hash computation failed");

		let err2 = VerifyMerkleProofError::InvalidProof("path length mismatch".to_string());
		assert_eq!(format!("{err2}"), "Invalid proof: path length mismatch");
	}
}
