//! Compute Commitment Use Case
//!
//! This use case encapsulates the business logic for computing a commitment
//! from a Note entity.
//!

//! This is part of the **Application Layer** (use cases), which orchestrates
//! domain services and entities to fulfill user intentions.
//!

//! Coordinate the computation of a commitment using domain services and entities.

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

	#[test]
	fn test_compute_commitment_success() {
		let use_case = ComputeCommitmentUseCase::new();

		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);

		let input = ComputeCommitmentInput { note };
		let hasher = MockHasher;

		let result = use_case.execute(input, hasher);
		assert!(result.is_ok());

		let output = result.unwrap();
		// Commitment should be deterministic
		assert_eq!(output.commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_compute_commitment_zero_note() {
		let use_case = ComputeCommitmentUseCase::new();

		let note = Note::zero();
		let input = ComputeCommitmentInput { note };
		let hasher = MockHasher;

		let result = use_case.execute(input, hasher);
		assert!(result.is_ok());
	}

	#[test]
	fn test_compute_commitment_deterministic() {
		let use_case = ComputeCommitmentUseCase::new();

		let note = Note::new(
			200,
			5,
			OwnerPubkey::from(Fr::from(999u64)),
			Blinding::from(Fr::from(111u64)),
		);

		let input1 = ComputeCommitmentInput { note: note.clone() };
		let input2 = ComputeCommitmentInput { note };

		let hasher = MockHasher;

		let output1 = use_case.execute(input1, MockHasher).unwrap();
		let output2 = use_case.execute(input2, hasher).unwrap();

		assert_eq!(output1.commitment, output2.commitment);
	}

	#[test]
	fn test_error_display() {
		let err = ComputeCommitmentError::HasherError("computation failed".to_string());
		assert_eq!(format!("{err}"), "Hasher error: computation failed");
	}
}
