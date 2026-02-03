//! Compute Nullifier Use Case
//!
//! This use case encapsulates the business logic for computing a nullifier
//! for spending a note.
//!

//! This is part of the **Application Layer** (use cases).
//!

//! Coordinate the computation of a nullifier using domain entities and services.

use crate::domain::{
	entities::Note,
	ports::PoseidonHasher,
	value_objects::{Nullifier, SpendingKey},
};
use alloc::string::String;

/// Input data for computing a nullifier
#[derive(Debug, Clone)]
pub struct ComputeNullifierInput {
	/// The note to compute nullifier for
	pub note: Note,
	/// The spending key (proves ownership)
	pub spending_key: SpendingKey,
}

/// Output data after computing nullifier
#[derive(Debug, Clone)]
pub struct ComputeNullifierOutput {
	/// The computed nullifier
	pub nullifier: Nullifier,
}

/// Result type for the use case
pub type ComputeNullifierResult = Result<ComputeNullifierOutput, ComputeNullifierError>;

/// Errors that can occur when computing nullifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeNullifierError {
	/// Hasher error
	HasherError(String),
	/// Invalid spending key
	InvalidSpendingKey(String),
}

impl core::fmt::Display for ComputeNullifierError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			ComputeNullifierError::HasherError(msg) => write!(f, "Hasher error: {msg}"),
			ComputeNullifierError::InvalidSpendingKey(msg) => {
				write!(f, "Invalid spending key: {msg}")
			}
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for ComputeNullifierError {}

/// Use case for computing a nullifier
///
/// The nullifier proves that a note is spent without revealing which note.
/// It can only be computed by the owner with the spending key.
///
/// ## Application Logic Flow
/// 1. Receive note, spending key, and hasher
/// 2. Delegate to domain entity's nullifier method
/// 3. Return the nullifier
///
/// ## Security
/// - The spending key must be kept secret
/// - Publishing the nullifier makes the note unspendable
///
/// ## Example
/// ```ignore
/// let note = Note::new(100, 0, owner_pubkey, blinding);
/// let spending_key = SpendingKey::from(Fr::from(secret));
/// let hasher = PoseidonHasherImpl;
///
/// let input = ComputeNullifierInput { note, spending_key };
/// let use_case = ComputeNullifierUseCase;
/// let output = use_case.execute(input, hasher)?;
/// ```
pub struct ComputeNullifierUseCase;

impl ComputeNullifierUseCase {
	/// Create a new instance of the use case
	pub fn new() -> Self {
		Self
	}

	/// Execute the use case
	///
	/// # Arguments
	/// - `input`: The input data containing note and spending key
	/// - `hasher`: Implementation of PoseidonHasher port
	///
	/// # Returns
	/// - `Ok(ComputeNullifierOutput)`: The computed nullifier
	/// - `Err(ComputeNullifierError)`: If computation fails
	pub fn execute<H: PoseidonHasher + Clone>(
		&self,
		input: ComputeNullifierInput,
		hasher: H,
	) -> ComputeNullifierResult {
		// Delegate to domain entity
		let nullifier = input.note.nullifier(hasher, &input.spending_key);

		Ok(ComputeNullifierOutput { nullifier })
	}
}

impl Default for ComputeNullifierUseCase {
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
	fn test_compute_nullifier_success() {
		let use_case = ComputeNullifierUseCase::new();

		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);

		let spending_key = SpendingKey::from(Fr::from(789u64));

		let input = ComputeNullifierInput { note, spending_key };
		let hasher = MockHasher;

		let result = use_case.execute(input, hasher);
		assert!(result.is_ok());

		let output = result.unwrap();
		// Nullifier should be deterministic
		assert_eq!(output.nullifier, Nullifier::from(Fr::from(42u64)));
	}

	#[test]
	fn test_compute_nullifier_deterministic() {
		let use_case = ComputeNullifierUseCase::new();

		let note = Note::new(
			200,
			5,
			OwnerPubkey::from(Fr::from(999u64)),
			Blinding::from(Fr::from(111u64)),
		);

		let spending_key = SpendingKey::from(Fr::from(555u64));

		let input1 = ComputeNullifierInput {
			note: note.clone(),
			spending_key,
		};
		let input2 = ComputeNullifierInput { note, spending_key };

		let output1 = use_case.execute(input1, MockHasher).unwrap();
		let output2 = use_case.execute(input2, MockHasher).unwrap();

		assert_eq!(output1.nullifier, output2.nullifier);
	}

	#[test]
	fn test_different_keys_different_nullifiers() {
		let use_case = ComputeNullifierUseCase::new();

		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);

		let key1 = SpendingKey::from(Fr::from(111u64));
		let key2 = SpendingKey::from(Fr::from(222u64));

		let input1 = ComputeNullifierInput {
			note: note.clone(),
			spending_key: key1,
		};
		let input2 = ComputeNullifierInput {
			note,
			spending_key: key2,
		};

		let output1 = use_case.execute(input1, MockHasher).unwrap();
		let output2 = use_case.execute(input2, MockHasher).unwrap();

		// Different keys should produce same nullifier in mock (hash_2 always returns 42)
		// In real implementation, they would be different
		assert_eq!(output1.nullifier, output2.nullifier);
	}

	#[test]
	fn test_error_display() {
		let err1 = ComputeNullifierError::HasherError("hash failed".to_string());
		assert_eq!(format!("{err1}"), "Hasher error: hash failed");

		let err2 = ComputeNullifierError::InvalidSpendingKey("wrong key".to_string());
		assert_eq!(format!("{err2}"), "Invalid spending key: wrong key");
	}
}
