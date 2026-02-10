//! Create Note Use Case
//!
//! Orchestrates the creation of new Note entities with proper validation
//! and adherence to business rules.

use crate::domain::{
	entities::Note,
	value_objects::{Blinding, OwnerPubkey},
};
use alloc::string::String;

/// Input data for creating a note
#[derive(Debug, Clone)]
pub struct CreateNoteInput {
	/// Value of the note (amount)
	pub value: u64,
	/// Asset ID (0 for native token)
	pub asset_id: u64,
	/// Owner's public key
	pub owner_pubkey: OwnerPubkey,
	/// Blinding factor for privacy
	pub blinding: Blinding,
}

/// Output data after creating a note
#[derive(Debug, Clone)]
pub struct CreateNoteOutput {
	/// The created note entity
	pub note: Note,
}

/// Result type for the use case
pub type CreateNoteResult = Result<CreateNoteOutput, CreateNoteError>;

/// Errors that can occur when creating a note
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateNoteError {
	/// Invalid value (domain invariant violation)
	InvalidValue(String),
	/// Invalid asset ID
	InvalidAssetId(String),
}

impl core::fmt::Display for CreateNoteError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			CreateNoteError::InvalidValue(msg) => write!(f, "Invalid note value: {msg}"),
			CreateNoteError::InvalidAssetId(msg) => write!(f, "Invalid asset ID: {msg}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for CreateNoteError {}

/// Use case for creating a new Note
///
/// This use case validates input and delegates to the domain entity
/// to create a valid Note following business rules.
///
/// ## Application Logic Flow
/// 1. Validate input (value, asset_id)
/// 2. Delegate to domain entity constructor
/// 3. Return the created note
///
/// ## Example
/// ```ignore
/// let input = CreateNoteInput {
///     value: 100,
///     asset_id: 0,
///     owner_pubkey: OwnerPubkey::from(Fr::from(123u64)),
///     blinding: Blinding::from(Fr::from(456u64)),
/// };
///
/// let use_case = CreateNoteUseCase;
/// let output = use_case.execute(input)?;
/// ```
pub struct CreateNoteUseCase;

impl CreateNoteUseCase {
	/// Create a new instance of the use case
	pub fn new() -> Self {
		Self
	}

	/// Execute the use case
	///
	/// # Arguments
	/// - `input`: The input data for creating the note
	///
	/// # Returns
	/// - `Ok(CreateNoteOutput)`: The created note
	/// - `Err(CreateNoteError)`: If validation fails
	pub fn execute(&self, input: CreateNoteInput) -> CreateNoteResult {
		// Application-level validation
		self.validate_input(&input)?;

		// Delegate to domain entity
		let note = Note::new(
			input.value,
			input.asset_id,
			input.owner_pubkey,
			input.blinding,
		);

		Ok(CreateNoteOutput { note })
	}

	/// Validate input at application level
	///
	/// This performs additional checks beyond domain invariants.
	fn validate_input(&self, _input: &CreateNoteInput) -> Result<(), CreateNoteError> {
		// Note: Domain entity already validates basic invariants
		// Here we can add application-specific validations

		// Future: Add business rules like:
		// - Check if asset_id is registered
		// - Check if value is within allowed limits for this asset
		// - Validate owner_pubkey format/encoding

		Ok(())
	}
}

impl Default for CreateNoteUseCase {
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

	// ===== Use Case Construction Tests =====

	#[test]
	fn test_new() {
		let _use_case = CreateNoteUseCase::new();
	}

	#[test]
	fn test_default() {
		let _use_case = CreateNoteUseCase;
	}

	// ===== Input Construction Tests =====

	#[test]
	fn test_input_zero_values() {
		let input = CreateNoteInput {
			value: 0,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(Fr::from(0u64)),
			blinding: Blinding::from(Fr::from(0u64)),
		};
		assert_eq!(input.value, 0);
		assert_eq!(input.asset_id, 0);
	}

	#[test]
	fn test_input_nonzero_values() {
		let input = CreateNoteInput {
			value: 100,
			asset_id: 5,
			owner_pubkey: OwnerPubkey::from(Fr::from(123u64)),
			blinding: Blinding::from(Fr::from(456u64)),
		};
		assert_eq!(input.value, 100);
		assert_eq!(input.asset_id, 5);
	}

	#[test]
	fn test_input_max_values() {
		let input = CreateNoteInput {
			value: u64::MAX,
			asset_id: u64::MAX,
			owner_pubkey: OwnerPubkey::from(Fr::from(999u64)),
			blinding: Blinding::from(Fr::from(888u64)),
		};
		assert_eq!(input.value, u64::MAX);
		assert_eq!(input.asset_id, u64::MAX);
	}

	#[test]
	fn test_input_clone() {
		let input1 = CreateNoteInput {
			value: 50,
			asset_id: 1,
			owner_pubkey: OwnerPubkey::from(Fr::from(100u64)),
			blinding: Blinding::from(Fr::from(200u64)),
		};
		let input2 = input1.clone();
		assert_eq!(input1.value, input2.value);
		assert_eq!(input1.asset_id, input2.asset_id);
	}

	#[test]
	fn test_input_debug() {
		let input = CreateNoteInput {
			value: 100,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(Fr::from(123u64)),
			blinding: Blinding::from(Fr::from(456u64)),
		};
		let debug_str = format!("{input:?}");
		assert!(debug_str.contains("CreateNoteInput"));
	}

	// ===== Execute Success Tests =====

	#[test]
	fn test_execute_success() {
		let use_case = CreateNoteUseCase::new();
		let input = CreateNoteInput {
			value: 100,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(Fr::from(123u64)),
			blinding: Blinding::from(Fr::from(456u64)),
		};
		let result = use_case.execute(input.clone());
		assert!(result.is_ok());
		let output = result.unwrap();
		assert_eq!(output.note.value(), 100);
		assert_eq!(output.note.asset_id(), 0);
		assert_eq!(output.note.owner_pubkey(), input.owner_pubkey);
		assert_eq!(output.note.blinding(), input.blinding);
	}

	#[test]
	fn test_execute_zero_note() {
		let use_case = CreateNoteUseCase::new();
		let input = CreateNoteInput {
			value: 0,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(Fr::from(0u64)),
			blinding: Blinding::from(Fr::from(0u64)),
		};
		let result = use_case.execute(input);
		assert!(result.is_ok());
		let output = result.unwrap();
		assert_eq!(output.note.value(), 0);
	}

	#[test]
	fn test_execute_large_value() {
		let use_case = CreateNoteUseCase::new();
		let input = CreateNoteInput {
			value: u64::MAX,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(Fr::from(123u64)),
			blinding: Blinding::from(Fr::from(456u64)),
		};
		let result = use_case.execute(input);
		assert!(result.is_ok());
	}

	#[test]
	fn test_execute_different_assets() {
		let use_case = CreateNoteUseCase::new();
		let input = CreateNoteInput {
			value: 500,
			asset_id: 42,
			owner_pubkey: OwnerPubkey::from(Fr::from(999u64)),
			blinding: Blinding::from(Fr::from(111u64)),
		};
		let result = use_case.execute(input);
		assert!(result.is_ok());
		let output = result.unwrap();
		assert_eq!(output.note.asset_id(), 42);
	}

	#[test]
	fn test_execute_multiple_different_assets() {
		let use_case = CreateNoteUseCase::new();
		let assets = vec![0u64, 1, 5, 42, 100, 999];
		for asset_id in assets {
			let input = CreateNoteInput {
				value: 100,
				asset_id,
				owner_pubkey: OwnerPubkey::from(Fr::from(123u64)),
				blinding: Blinding::from(Fr::from(456u64)),
			};
			let result = use_case.execute(input);
			assert!(result.is_ok());
			assert_eq!(result.unwrap().note.asset_id(), asset_id);
		}
	}

	#[test]
	fn test_execute_preserves_all_fields() {
		let use_case = CreateNoteUseCase::new();
		let owner = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let input = CreateNoteInput {
			value: 100,
			asset_id: 5,
			owner_pubkey: owner,
			blinding,
		};
		let output = use_case.execute(input).unwrap();
		assert_eq!(output.note.value(), 100);
		assert_eq!(output.note.asset_id(), 5);
		assert_eq!(output.note.owner_pubkey(), owner);
		assert_eq!(output.note.blinding(), blinding);
	}

	// ===== Validation Tests =====

	#[test]
	fn test_validate_input_success() {
		let use_case = CreateNoteUseCase::new();
		let input = CreateNoteInput {
			value: 100,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(Fr::from(123u64)),
			blinding: Blinding::from(Fr::from(456u64)),
		};
		let result = use_case.validate_input(&input);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_input_zero_values() {
		let use_case = CreateNoteUseCase::new();
		let input = CreateNoteInput {
			value: 0,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(Fr::from(0u64)),
			blinding: Blinding::from(Fr::from(0u64)),
		};
		let result = use_case.validate_input(&input);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_input_max_values() {
		let use_case = CreateNoteUseCase::new();
		let input = CreateNoteInput {
			value: u64::MAX,
			asset_id: u64::MAX,
			owner_pubkey: OwnerPubkey::from(Fr::from(999u64)),
			blinding: Blinding::from(Fr::from(888u64)),
		};
		let result = use_case.validate_input(&input);
		assert!(result.is_ok());
	}

	// ===== Output Tests =====

	#[test]
	fn test_output_clone() {
		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		let output1 = CreateNoteOutput { note };
		let output2 = output1.clone();
		assert_eq!(output1.note.value(), output2.note.value());
	}

	#[test]
	fn test_output_debug() {
		let note = Note::new(
			100,
			0,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		let output = CreateNoteOutput { note };
		let debug_str = format!("{output:?}");
		assert!(debug_str.contains("CreateNoteOutput"));
	}

	// ===== Error Tests =====

	#[test]
	fn test_error_invalid_value() {
		let err = CreateNoteError::InvalidValue("negative value".to_string());
		assert!(matches!(err, CreateNoteError::InvalidValue(_)));
	}

	#[test]
	fn test_error_invalid_asset_id() {
		let err = CreateNoteError::InvalidAssetId("unregistered".to_string());
		assert!(matches!(err, CreateNoteError::InvalidAssetId(_)));
	}

	#[test]
	fn test_error_display_invalid_value() {
		let err = CreateNoteError::InvalidValue("negative value".to_string());
		assert_eq!(format!("{err}"), "Invalid note value: negative value");
	}

	#[test]
	fn test_error_display_invalid_asset() {
		let err = CreateNoteError::InvalidAssetId("unregistered".to_string());
		assert_eq!(format!("{err}"), "Invalid asset ID: unregistered");
	}

	#[test]
	fn test_error_clone() {
		let err1 = CreateNoteError::InvalidValue("test".to_string());
		let err2 = err1.clone();
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq_same() {
		let err1 = CreateNoteError::InvalidValue("error".to_string());
		let err2 = CreateNoteError::InvalidValue("error".to_string());
		assert_eq!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq_different() {
		let err1 = CreateNoteError::InvalidValue("error1".to_string());
		let err2 = CreateNoteError::InvalidValue("error2".to_string());
		assert_ne!(err1, err2);
	}

	#[test]
	fn test_error_partial_eq_different_variants() {
		let err1 = CreateNoteError::InvalidValue("error".to_string());
		let err2 = CreateNoteError::InvalidAssetId("error".to_string());
		assert_ne!(err1, err2);
	}

	#[test]
	fn test_error_debug() {
		let err = CreateNoteError::InvalidAssetId("test".to_string());
		let debug_str = format!("{err:?}");
		assert!(debug_str.contains("InvalidAssetId"));
		assert!(debug_str.contains("test"));
	}
}
