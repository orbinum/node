//! Compute Nullifier Use Case
//!
//! Orchestrates the computation of a nullifier for spending a note,
//! proving ownership through the spending key.

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
	extern crate alloc;
	use alloc::{format, string::ToString};

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
		let _use_case = ComputeNullifierUseCase::new();
	}

	#[test]
	fn test_default() {
		let _use_case = ComputeNullifierUseCase;
	}

	// ===== Input Construction Tests =====

	#[test]
	fn test_input_with_zero_note() {
		let note = Note::zero();
		let spending_key = SpendingKey::from(Fr::from(123u64));
		let input = ComputeNullifierInput {
			note: note.clone(),
			spending_key,
		};
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
		let spending_key = SpendingKey::from(Fr::from(789u64));
		let input = ComputeNullifierInput { note, spending_key };
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
		let spending_key = SpendingKey::from(Fr::from(300u64));
		let input1 = ComputeNullifierInput { note, spending_key };
		let input2 = input1.clone();
		assert_eq!(input1.note.value(), input2.note.value());
	}

	#[test]
	fn test_input_different_spending_keys() {
		let note = Note::zero();
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
		assert_ne!(input1.spending_key, input2.spending_key);
	}

	// ===== Execute Tests =====

	#[test]
	fn test_execute_success() {
		let use_case = ComputeNullifierUseCase::new();
		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		let spending_key = SpendingKey::from(Fr::from(789u64));
		let input = ComputeNullifierInput { note, spending_key };
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	#[test]
	fn test_execute_zero_note() {
		let use_case = ComputeNullifierUseCase::new();
		let note = Note::zero();
		let spending_key = SpendingKey::from(Fr::from(123u64));
		let input = ComputeNullifierInput { note, spending_key };
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	#[test]
	fn test_execute_large_value() {
		let use_case = ComputeNullifierUseCase::new();
		let note = Note::new(
			u64::MAX,
			u64::MAX,
			OwnerPubkey::from(Fr::from(999u64)),
			Blinding::from(Fr::from(888u64)),
		);
		let spending_key = SpendingKey::from(Fr::from(777u64));
		let input = ComputeNullifierInput { note, spending_key };
		let result = use_case.execute(input, MockHasher);
		assert!(result.is_ok());
	}

	#[test]
	fn test_execute_deterministic() {
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
	fn test_execute_nullifier_value() {
		let use_case = ComputeNullifierUseCase::new();
		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		let spending_key = SpendingKey::from(Fr::from(789u64));
		let input = ComputeNullifierInput { note, spending_key };
		let output = use_case.execute(input, MockHasher).unwrap();
		// MockHasher returns 42 for hash_2 (commitment + spending_key)
		assert_eq!(output.nullifier, Nullifier::from(Fr::from(42u64)));
	}

	#[test]
	fn test_different_spending_keys() {
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
		// MockHasher always returns same value, in real impl would differ
		assert_eq!(output1.nullifier, output2.nullifier);
	}

	#[test]
	fn test_different_notes_same_key() {
		let use_case = ComputeNullifierUseCase::new();
		let note1 = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		let note2 = Note::new(
			200,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(789u64)),
		);
		let spending_key = SpendingKey::from(Fr::from(555u64));
		let input1 = ComputeNullifierInput {
			note: note1,
			spending_key,
		};
		let input2 = ComputeNullifierInput {
			note: note2,
			spending_key,
		};
		let output1 = use_case.execute(input1, MockHasher).unwrap();
		let output2 = use_case.execute(input2, MockHasher).unwrap();
		// MockHasher returns same, but in real impl would differ
		assert_eq!(output1.nullifier, output2.nullifier);
	}

	// ===== Output Tests =====

	#[test]
	fn test_output_clone() {
		let nullifier = Nullifier::from(Fr::from(42u64));
		let output1 = ComputeNullifierOutput { nullifier };
		let output2 = output1.clone();
		assert_eq!(output1.nullifier, output2.nullifier);
	}

	#[test]
	fn test_output_debug() {
		let nullifier = Nullifier::from(Fr::from(42u64));
		let output = ComputeNullifierOutput { nullifier };
		let debug_str = format!("{output:?}");
		assert!(debug_str.contains("ComputeNullifierOutput"));
	}

	// ===== Error Tests =====

	#[test]
	fn test_error_hasher_error() {
		let err = ComputeNullifierError::HasherError("hash failed".to_string());
		assert!(matches!(err, ComputeNullifierError::HasherError(_)));
	}

	#[test]
	fn test_error_invalid_spending_key() {
		let err = ComputeNullifierError::InvalidSpendingKey("wrong key".to_string());
		assert!(matches!(err, ComputeNullifierError::InvalidSpendingKey(_)));
	}

	#[test]
	fn test_error_display_hasher() {
		let err = ComputeNullifierError::HasherError("hash failed".to_string());
		assert_eq!(format!("{err}"), "Hasher error: hash failed");
	}

	#[test]
	fn test_error_display_invalid_key() {
		let err = ComputeNullifierError::InvalidSpendingKey("wrong key".to_string());
		assert_eq!(format!("{err}"), "Invalid spending key: wrong key");
	}

	#[test]
	fn test_error_clone() {
		let err1 = ComputeNullifierError::HasherError("test".to_string());
		let err2 = err1.clone();
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq_same() {
		let err1 = ComputeNullifierError::HasherError("error".to_string());
		let err2 = ComputeNullifierError::HasherError("error".to_string());
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq_different() {
		let err1 = ComputeNullifierError::HasherError("error1".to_string());
		let err2 = ComputeNullifierError::HasherError("error2".to_string());
		assert_ne!(err1, err2);
	}

	#[test]
	fn test_error_debug() {
		let err = ComputeNullifierError::InvalidSpendingKey("test".to_string());
		let debug_str = format!("{err:?}");
		assert!(debug_str.contains("InvalidSpendingKey"));
		assert!(debug_str.contains("test"));
	}
}
