//! Verify Merkle Proof Use Case
//!
//! Orchestrates the verification of Merkle proofs using domain services,
//! confirming commitment inclusion in the Merkle tree.

use crate::domain::{
	ports::PoseidonHasher,
	services::MerkleService,
	value_objects::{Commitment, FieldElement},
};
use alloc::{string::String, vec::Vec};

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
	extern crate alloc;
	use alloc::{format, string::ToString, vec};

	struct MockHasher;

	impl PoseidonHasher for MockHasher {
		fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
			// Simple deterministic mock: just return first input
			inputs[0]
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	// ===== Use Case Construction Tests =====

	#[test]
	fn test_new() {
		let _use_case = VerifyMerkleProofUseCase::new();
	}

	#[test]
	fn test_default() {
		let _use_case = VerifyMerkleProofUseCase;
	}

	// ===== Input Construction Tests =====

	#[test]
	fn test_input_empty_siblings() {
		let commitment = Commitment::from(Fr::from(42u64));
		let siblings = vec![];
		let root = FieldElement::from_u64(42);
		let input = VerifyMerkleProofInput {
			commitment,
			siblings,
			root,
		};
		assert_eq!(input.siblings.len(), 0);
	}

	#[test]
	fn test_input_single_sibling() {
		let commitment = Commitment::from(Fr::from(10u64));
		let siblings = vec![FieldElement::from_u64(20)];
		let root = FieldElement::from_u64(30);
		let input = VerifyMerkleProofInput {
			commitment,
			siblings,
			root,
		};
		assert_eq!(input.siblings.len(), 1);
	}

	#[test]
	fn test_input_multiple_siblings() {
		let commitment = Commitment::from(Fr::from(1u64));
		let siblings = vec![
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];
		let root = FieldElement::from_u64(10);
		let input = VerifyMerkleProofInput {
			commitment,
			siblings,
			root,
		};
		assert_eq!(input.siblings.len(), 3);
	}

	#[test]
	fn test_input_clone() {
		let commitment = Commitment::from(Fr::from(42u64));
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let root = FieldElement::from_u64(99);
		let input1 = VerifyMerkleProofInput {
			commitment,
			siblings,
			root,
		};
		let input2 = input1.clone();
		assert_eq!(input1.commitment, input2.commitment);
		assert_eq!(input1.siblings.len(), input2.siblings.len());
	}

	#[test]
	fn test_input_debug() {
		let commitment = Commitment::from(Fr::from(42u64));
		let siblings = vec![FieldElement::from_u64(1)];
		let root = FieldElement::from_u64(99);
		let input = VerifyMerkleProofInput {
			commitment,
			siblings,
			root,
		};
		let debug_str = format!("{input:?}");
		assert!(debug_str.contains("VerifyMerkleProofInput"));
	}

	// ===== Execute Valid Proof Tests =====

	#[test]
	fn test_execute_valid_proof() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf_value = Fr::from(42u64);
		let leaf = Commitment::from(leaf_value);
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let root = FieldElement::from(leaf_value); // MockHasher returns first input
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
		let output = result.unwrap();
		assert!(output.is_valid);
	}

	#[test]
	fn test_execute_valid_empty_path() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf = Commitment::from(Fr::from(42u64));
		let siblings = vec![];
		let root = FieldElement::from_u64(42);
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
		let output = result.unwrap();
		assert!(output.is_valid);
	}

	#[test]
	fn test_execute_valid_zero_commitment() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf = Commitment::from(Fr::from(0u64));
		let siblings = vec![FieldElement::from_u64(0)];
		let root = FieldElement::from_u64(0);
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	// ===== Execute Invalid Proof Tests =====

	#[test]
	fn test_execute_invalid_proof() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf = Commitment::from(Fr::from(10u64));
		let siblings = vec![FieldElement::from_u64(5)];
		let root = FieldElement::from_u64(20); // Wrong root
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
		let output = result.unwrap();
		assert!(!output.is_valid);
	}

	#[test]
	fn test_execute_invalid_wrong_root() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf = Commitment::from(Fr::from(100u64));
		let siblings = vec![FieldElement::from_u64(200)];
		let root = FieldElement::from_u64(999); // Wrong root
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
		assert!(!result.unwrap().is_valid);
	}

	#[test]
	fn test_execute_invalid_empty_path_wrong_root() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf = Commitment::from(Fr::from(42u64));
		let siblings = vec![];
		let root = FieldElement::from_u64(99); // Should be 42
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
		assert!(!result.unwrap().is_valid);
	}

	// ===== Execute With Different Paths Tests =====

	#[test]
	fn test_execute_single_sibling() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf = Commitment::from(Fr::from(10u64));
		let siblings = vec![FieldElement::from_u64(20)];
		let root = FieldElement::from_u64(10); // MockHasher returns first input
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	#[test]
	fn test_execute_deep_path() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf = Commitment::from(Fr::from(1u64));
		let siblings = vec![
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
			FieldElement::from_u64(5),
			FieldElement::from_u64(6),
		];
		let root = FieldElement::from_u64(1); // MockHasher returns first input
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
		assert!(result.unwrap().is_valid);
	}

	#[test]
	fn test_execute_max_depth() {
		let use_case = VerifyMerkleProofUseCase::new();
		let leaf = Commitment::from(Fr::from(1u64));
		let siblings: Vec<FieldElement> = (0..32).map(FieldElement::from_u64).collect();
		let root = FieldElement::from_u64(1);
		let input = VerifyMerkleProofInput {
			commitment: leaf,
			siblings,
			root,
		};
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	// ===== Output Tests =====

	#[test]
	fn test_output_valid() {
		let output = VerifyMerkleProofOutput { is_valid: true };
		assert!(output.is_valid);
	}

	#[test]
	fn test_output_invalid() {
		let output = VerifyMerkleProofOutput { is_valid: false };
		assert!(!output.is_valid);
	}

	#[test]
	fn test_output_clone() {
		let output1 = VerifyMerkleProofOutput { is_valid: true };
		let output2 = output1.clone();
		assert_eq!(output1.is_valid, output2.is_valid);
	}

	#[test]
	fn test_output_debug() {
		let output = VerifyMerkleProofOutput { is_valid: true };
		let debug_str = format!("{output:?}");
		assert!(debug_str.contains("VerifyMerkleProofOutput"));
	}

	// ===== Error Tests =====

	#[test]
	fn test_error_hasher_error() {
		let err = VerifyMerkleProofError::HasherError("hash failed".to_string());
		assert!(matches!(err, VerifyMerkleProofError::HasherError(_)));
	}

	#[test]
	fn test_error_invalid_proof() {
		let err = VerifyMerkleProofError::InvalidProof("path mismatch".to_string());
		assert!(matches!(err, VerifyMerkleProofError::InvalidProof(_)));
	}

	#[test]
	fn test_error_display_hasher() {
		let err = VerifyMerkleProofError::HasherError("hash computation failed".to_string());
		assert_eq!(format!("{err}"), "Hasher error: hash computation failed");
	}

	#[test]
	fn test_error_display_invalid_proof() {
		let err = VerifyMerkleProofError::InvalidProof("path length mismatch".to_string());
		assert_eq!(format!("{err}"), "Invalid proof: path length mismatch");
	}

	#[test]
	fn test_error_clone() {
		let err1 = VerifyMerkleProofError::HasherError("test".to_string());
		let err2 = err1.clone();
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq_same() {
		let err1 = VerifyMerkleProofError::HasherError("error".to_string());
		let err2 = VerifyMerkleProofError::HasherError("error".to_string());
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq_different() {
		let err1 = VerifyMerkleProofError::HasherError("error1".to_string());
		let err2 = VerifyMerkleProofError::HasherError("error2".to_string());
		assert_ne!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq_different_variants() {
		let err1 = VerifyMerkleProofError::HasherError("error".to_string());
		let err2 = VerifyMerkleProofError::InvalidProof("error".to_string());
		assert_ne!(err1, err2);
	}

	#[test]
	fn test_error_debug() {
		let err = VerifyMerkleProofError::InvalidProof("test".to_string());
		let debug_str = format!("{err:?}");
		assert!(debug_str.contains("InvalidProof"));
		assert!(debug_str.contains("test"));
	}
}
