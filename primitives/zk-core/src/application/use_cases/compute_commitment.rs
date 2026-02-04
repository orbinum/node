//! Compute Commitment Use Case
//!
//! Orchestrates the computation of a cryptographic commitment from a Note entity
//! using domain services and the Poseidon hasher.

use crate::domain::{entities::Note, ports::PoseidonHasher, value_objects::Commitment};
use alloc::string::String;

/// Input data for computing a commitment
#[derive(Debug, Clone)]
pub struct ComputeCommitmentInput {
	/// The note to compute commitment for
	pub note: Note,
}

/// Output data after computing commitment
#[derive(Debug, Clone)]
pub struct ComputeCommitmentOutput {
	/// The computed commitment
	pub commitment: Commitment,
}

/// Result type for the use case
pub type ComputeCommitmentResult = Result<ComputeCommitmentOutput, ComputeCommitmentError>;

/// Errors that can occur when computing commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeCommitmentError {
	/// Hasher error
	HasherError(String),
}

impl core::fmt::Display for ComputeCommitmentError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			ComputeCommitmentError::HasherError(msg) => write!(f, "Hasher error: {msg}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for ComputeCommitmentError {}

/// Use case for computing a note commitment
///
/// This use case takes a Note and produces its cryptographic commitment
/// using the provided hasher implementation.
///
/// ## Application Logic Flow
/// 1. Receive note and hasher
/// 2. Delegate to domain entity's commitment method
/// 3. Return the commitment
///
/// ## Example
/// ```ignore
/// let note = Note::new(100, 0, owner_pubkey, blinding);
/// let hasher = PoseidonHasherImpl;
///
/// let input = ComputeCommitmentInput { note };
/// let use_case = ComputeCommitmentUseCase;
/// let output = use_case.execute(input, hasher)?;
/// ```
pub struct ComputeCommitmentUseCase;

impl ComputeCommitmentUseCase {
	/// Create a new instance of the use case
	pub fn new() -> Self {
		Self
	}

	/// Execute the use case
	///
	/// # Arguments
	/// - `input`: The input data containing the note
	/// - `hasher`: Implementation of PoseidonHasher port
	///
	/// # Returns
	/// - `Ok(ComputeCommitmentOutput)`: The computed commitment
	/// - `Err(ComputeCommitmentError)`: If computation fails
	pub fn execute<H: PoseidonHasher + Clone>(
		&self,
		input: ComputeCommitmentInput,
		hasher: H,
	) -> ComputeCommitmentResult {
		// Delegate to domain entity
		let commitment = input.note.commitment(hasher);

		Ok(ComputeCommitmentOutput { commitment })
	}
}

impl Default for ComputeCommitmentUseCase {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::domain::value_objects::{Blinding, FieldElement, OwnerPubkey};
	use ark_bn254::Fr;
	extern crate alloc;
	use alloc::format;
	use alloc::string::ToString;

	#[derive(Clone)]
	struct MockHasher;

	impl PoseidonHasher for MockHasher {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	// ===== Use Case Construction Tests =====

	#[test]
	fn test_new() {
		let _use_case = ComputeCommitmentUseCase::new();
	}

	#[test]
	fn test_default() {
		let _use_case = ComputeCommitmentUseCase;
	}

	// ===== Input Construction Tests =====

	#[test]
	fn test_input_with_zero_note() {
		let note = Note::zero();
		let input = ComputeCommitmentInput { note: note.clone() };
		assert_eq!(input.note.value(), note.value());
	}

	#[test]
	fn test_input_with_nonzero_note() {
		let note = Note::new(
			100,
			5,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		let input = ComputeCommitmentInput { note: note.clone() };
		assert_eq!(input.note.value(), 100);
		assert_eq!(input.note.asset_id(), 5);
	}

	#[test]
	fn test_input_clone() {
		let note = Note::new(
			50,
			1,
			OwnerPubkey::from(Fr::from(100u64)),
			Blinding::from(Fr::from(200u64)),
		);
		let input1 = ComputeCommitmentInput { note };
		let input2 = input1.clone();
		assert_eq!(input1.note.value(), input2.note.value());
	}

	// ===== Execute Tests =====

	#[test]
	fn test_execute_success() {
		let use_case = ComputeCommitmentUseCase::new();
		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		let input = ComputeCommitmentInput { note };
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	#[test]
	fn test_execute_zero_note() {
		let use_case = ComputeCommitmentUseCase::new();
		let note = Note::zero();
		let input = ComputeCommitmentInput { note };
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	#[test]
	fn test_execute_large_value() {
		let use_case = ComputeCommitmentUseCase::new();
		let note = Note::new(
			u64::MAX,
			u64::MAX,
			OwnerPubkey::from(Fr::from(999u64)),
			Blinding::from(Fr::from(888u64)),
		);
		let input = ComputeCommitmentInput { note };
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	#[test]
	fn test_execute_deterministic() {
		let use_case = ComputeCommitmentUseCase::new();
		let note = Note::new(
			200,
			5,
			OwnerPubkey::from(Fr::from(999u64)),
			Blinding::from(Fr::from(111u64)),
		);
		let input1 = ComputeCommitmentInput { note: note.clone() };
		let input2 = ComputeCommitmentInput { note };
		let output1 = use_case.execute(input1, MockHasher).unwrap();
		let output2 = use_case.execute(input2, MockHasher).unwrap();
		assert_eq!(output1.commitment, output2.commitment);
	}

	#[test]
	fn test_execute_commitment_value() {
		let use_case = ComputeCommitmentUseCase::new();
		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		let input = ComputeCommitmentInput { note };
		let output = use_case.execute(input, MockHasher).unwrap();
		// MockHasher returns 100 for hash_4
		assert_eq!(output.commitment, Commitment::from(Fr::from(100u64)));
	}

	// ===== Output Tests =====

	#[test]
	fn test_output_clone() {
		let commitment = Commitment::from(Fr::from(42u64));
		let output1 = ComputeCommitmentOutput { commitment };
		let output2 = output1.clone();
		assert_eq!(output1.commitment, output2.commitment);
	}

	#[test]
	fn test_output_debug() {
		let commitment = Commitment::from(Fr::from(42u64));
		let output = ComputeCommitmentOutput { commitment };
		let debug_str = format!("{output:?}");
		assert!(debug_str.contains("ComputeCommitmentOutput"));
	}

	// ===== Error Tests =====

	#[test]
	fn test_error_hasher_error() {
		let err = ComputeCommitmentError::HasherError("computation failed".to_string());
		assert!(matches!(err, ComputeCommitmentError::HasherError(_)));
	}

	#[test]
	fn test_error_display() {
		let err = ComputeCommitmentError::HasherError("computation failed".to_string());
		assert_eq!(format!("{err}"), "Hasher error: computation failed");
	}

	#[test]
	fn test_error_clone() {
		let err1 = ComputeCommitmentError::HasherError("test error".to_string());
		let err2 = err1.clone();
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq() {
		let err1 = ComputeCommitmentError::HasherError("error1".to_string());
		let err2 = ComputeCommitmentError::HasherError("error1".to_string());
		let err3 = ComputeCommitmentError::HasherError("error2".to_string());
		assert_eq!(err1, err2);
		assert_ne!(err1, err3);
	}

	#[test]
	fn test_error_debug() {
		let err = ComputeCommitmentError::HasherError("test".to_string());
		let debug_str = format!("{err:?}");
		assert!(debug_str.contains("HasherError"));
		assert!(debug_str.contains("test"));
	}
}
