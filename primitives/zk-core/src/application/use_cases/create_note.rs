//! Create Note Use Case
//!
//! This use case encapsulates the business logic for creating a new Note entity.
//!

//! This is part of the **Application Layer** (use cases), which:
//! - Orchestrates domain objects to fulfill specific user intentions
//! - Depends on domain layer (inner circle)
//! - Is independent of infrastructure details
//!

//! Coordinate the creation of a Note entity with proper validation and business rules.

use alloc::string::String;
use crate::domain::{
	entities::Note,
	value_objects::{Blinding, OwnerPubkey},
};

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

	#[test]
	fn test_create_note_success() {
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
	fn test_create_zero_note() {
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
	fn test_create_note_with_different_assets() {
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
	fn test_error_display() {
		let err = CreateNoteError::InvalidValue("negative value".to_string());
		assert_eq!(format!("{err}"), "Invalid note value: negative value");

		let err2 = CreateNoteError::InvalidAssetId("unregistered".to_string());
		assert_eq!(format!("{err2}"), "Invalid asset ID: unregistered");
	}
}
