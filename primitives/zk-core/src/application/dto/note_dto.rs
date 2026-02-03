//! Note Data Transfer Object
//!
//! This DTO represents a Note for external APIs and serialization.
//!

//! DTOs are part of the **Application Layer** and serve as:
//! - Data contracts for external APIs
//! - Serialization/deserialization boundary
//! - Translation layer between domain and external world
//!

//! - Isolate domain entities from serialization concerns
//! - Provide stable API contracts
//! - Convert between domain entities and external representations

use alloc::string::String;
use crate::domain::{
	entities::Note,
	value_objects::{Blinding, OwnerPubkey},
};
use ark_bn254::Fr;

/// Data Transfer Object for Note
///
/// This represents a note in a format suitable for external APIs,
/// serialization, and database storage.
///
/// ## Serialization
/// All fields use primitive types (u64, [u8; 32]) for easy serialization
/// to JSON, protobuf, or other formats.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct NoteDto {
	/// Value of the note (amount)
	pub value: u64,
	/// Asset ID (0 for native token)
	pub asset_id: u64,
	/// Owner's public key (32 bytes)
	pub owner_pubkey: [u8; 32],
	/// Blinding factor (32 bytes)
	pub blinding: [u8; 32],
}

impl NoteDto {
	/// Create a new NoteDto
	pub fn new(value: u64, asset_id: u64, owner_pubkey: [u8; 32], blinding: [u8; 32]) -> Self {
		Self {
			value,
			asset_id,
			owner_pubkey,
			blinding,
		}
	}

	/// Convert from domain Note entity
	///
	/// This maps the domain entity to a DTO suitable for external APIs.
	pub fn from_domain(note: &Note) -> Self {
		Self {
			value: note.value(),
			asset_id: note.asset_id(),
			owner_pubkey: Self::field_to_bytes(&note.owner_pubkey().inner().inner()),
			blinding: Self::field_to_bytes(&note.blinding().inner().inner()),
		}
	}

	/// Convert to domain Note entity
	///
	/// This maps the DTO back to a domain entity for business logic.
	///
	/// # Returns
	/// - `Ok(Note)`: Successfully converted to domain entity
	/// - `Err(String)`: If conversion fails (invalid field values)
	pub fn to_domain(&self) -> Result<Note, String> {
		let owner_pubkey = OwnerPubkey::from(Self::bytes_to_field(&self.owner_pubkey)?);
		let blinding = Blinding::from(Self::bytes_to_field(&self.blinding)?);

		Ok(Note::new(self.value, self.asset_id, owner_pubkey, blinding))
	}

	/// Convert field element to bytes
	fn field_to_bytes(field: &Fr) -> [u8; 32] {
		use ark_ff::PrimeField;
		let mut bytes = [0u8; 32];
		// Use arkworks serialization API
		let bigint = field.into_bigint();
		// Extract bytes from BigInt (4 limbs of 64 bits each)
		for (i, limb) in bigint.0.iter().enumerate() {
			let start = i * 8;
			if start < 32 {
				let limb_bytes = limb.to_le_bytes();
				let len = core::cmp::min(8, 32 - start);
				bytes[start..start + len].copy_from_slice(&limb_bytes[..len]);
			}
		}
		bytes
	}

	/// Convert bytes to field element
	fn bytes_to_field(bytes: &[u8; 32]) -> Result<Fr, String> {
		use ark_ff::PrimeField;
		Fr::from_le_bytes_mod_order(bytes);
		Ok(Fr::from_le_bytes_mod_order(bytes))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_note_dto_creation() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let dto = NoteDto::new(100, 0, owner_pubkey, blinding);

		assert_eq!(dto.value, 100);
		assert_eq!(dto.asset_id, 0);
		assert_eq!(dto.owner_pubkey, owner_pubkey);
		assert_eq!(dto.blinding, blinding);
	}

	#[test]
	fn test_from_domain() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 0, owner_pubkey, blinding);

		let dto = NoteDto::from_domain(&note);

		assert_eq!(dto.value, 100);
		assert_eq!(dto.asset_id, 0);
	}

	#[test]
	fn test_to_domain() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];
		let dto = NoteDto::new(100, 0, owner_pubkey, blinding);

		let result = dto.to_domain();
		assert!(result.is_ok());

		let note = result.unwrap();
		assert_eq!(note.value(), 100);
		assert_eq!(note.asset_id(), 0);
	}

	#[test]
	fn test_round_trip() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(999u64));
		let blinding = Blinding::from(Fr::from(111u64));
		let original_note = Note::new(500, 42, owner_pubkey, blinding);

		// Domain -> DTO -> Domain
		let dto = NoteDto::from_domain(&original_note);
		let converted_note = dto.to_domain().unwrap();

		assert_eq!(converted_note.value(), original_note.value());
		assert_eq!(converted_note.asset_id(), original_note.asset_id());
	}

	#[test]
	fn test_dto_equality() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let dto1 = NoteDto::new(100, 0, owner_pubkey, blinding);
		let dto2 = NoteDto::new(100, 0, owner_pubkey, blinding);

		assert_eq!(dto1, dto2);
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_serialization() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];
		let dto = NoteDto::new(100, 0, owner_pubkey, blinding);

		// Test JSON serialization
		let json = serde_json::to_string(&dto).unwrap();
		let deserialized: NoteDto = serde_json::from_str(&json).unwrap();

		assert_eq!(dto, deserialized);
	}
}
