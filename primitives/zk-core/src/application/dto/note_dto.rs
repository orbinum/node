//! Note Data Transfer Object
//!
//! DTO representing a note for external APIs and serialization.
//!
//! Provides the translation layer between domain entity [`Note`]
//! and external representations, isolating domain from serialization concerns.

use crate::domain::{
	entities::Note,
	value_objects::{Blinding, OwnerPubkey},
};
use alloc::string::String;
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
	extern crate alloc;
	use alloc::format;

	// new() tests
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
	fn test_new_with_zero_value() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let dto = NoteDto::new(0, 0, owner_pubkey, blinding);

		assert_eq!(dto.value, 0);
	}

	#[test]
	fn test_new_with_max_value() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let dto = NoteDto::new(u64::MAX, u64::MAX, owner_pubkey, blinding);

		assert_eq!(dto.value, u64::MAX);
		assert_eq!(dto.asset_id, u64::MAX);
	}

	#[test]
	fn test_new_with_different_asset_ids() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let dto1 = NoteDto::new(100, 0, owner_pubkey, blinding);
		let dto2 = NoteDto::new(100, 1, owner_pubkey, blinding);
		let dto3 = NoteDto::new(100, 999, owner_pubkey, blinding);

		assert_eq!(dto1.asset_id, 0);
		assert_eq!(dto2.asset_id, 1);
		assert_eq!(dto3.asset_id, 999);
	}

	#[test]
	fn test_new_with_zero_bytes() {
		let owner_pubkey = [0u8; 32];
		let blinding = [0u8; 32];

		let dto = NoteDto::new(100, 0, owner_pubkey, blinding);

		assert_eq!(dto.owner_pubkey, [0u8; 32]);
		assert_eq!(dto.blinding, [0u8; 32]);
	}

	#[test]
	fn test_new_with_max_bytes() {
		let owner_pubkey = [0xFFu8; 32];
		let blinding = [0xFFu8; 32];

		let dto = NoteDto::new(100, 0, owner_pubkey, blinding);

		assert_eq!(dto.owner_pubkey, [0xFFu8; 32]);
		assert_eq!(dto.blinding, [0xFFu8; 32]);
	}

	// from_domain() tests
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
	fn test_from_domain_zero_value() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(0u64));
		let blinding = Blinding::from(Fr::from(0u64));
		let note = Note::new(0, 0, owner_pubkey, blinding);

		let dto = NoteDto::from_domain(&note);

		assert_eq!(dto.value, 0);
		assert_eq!(dto.asset_id, 0);
	}

	#[test]
	fn test_from_domain_large_values() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(u64::MAX));
		let blinding = Blinding::from(Fr::from(u64::MAX));
		let note = Note::new(u64::MAX, u64::MAX, owner_pubkey, blinding);

		let dto = NoteDto::from_domain(&note);

		assert_eq!(dto.value, u64::MAX);
		assert_eq!(dto.asset_id, u64::MAX);
	}

	#[test]
	fn test_from_domain_different_asset_ids() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));

		let note1 = Note::new(100, 0, owner_pubkey, blinding);
		let note2 = Note::new(100, 1, owner_pubkey, blinding);
		let note3 = Note::new(100, 42, owner_pubkey, blinding);

		let dto1 = NoteDto::from_domain(&note1);
		let dto2 = NoteDto::from_domain(&note2);
		let dto3 = NoteDto::from_domain(&note3);

		assert_eq!(dto1.asset_id, 0);
		assert_eq!(dto2.asset_id, 1);
		assert_eq!(dto3.asset_id, 42);
	}

	#[test]
	fn test_from_domain_different_values() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));

		let values = [0u64, 1, 100, 1000, 999999, u64::MAX];
		for value in values {
			let note = Note::new(value, 0, owner_pubkey, blinding);
			let dto = NoteDto::from_domain(&note);
			assert_eq!(dto.value, value);
		}
	}

	// to_domain() tests
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
	fn test_to_domain_zero_values() {
		let owner_pubkey = [0u8; 32];
		let blinding = [0u8; 32];
		let dto = NoteDto::new(0, 0, owner_pubkey, blinding);

		let result = dto.to_domain();
		assert!(result.is_ok());

		let note = result.unwrap();
		assert_eq!(note.value(), 0);
		assert_eq!(note.asset_id(), 0);
	}

	#[test]
	fn test_to_domain_large_values() {
		let owner_pubkey = [0xFFu8; 32];
		let blinding = [0xFFu8; 32];
		let dto = NoteDto::new(u64::MAX, u64::MAX, owner_pubkey, blinding);

		let result = dto.to_domain();
		assert!(result.is_ok());

		let note = result.unwrap();
		assert_eq!(note.value(), u64::MAX);
		assert_eq!(note.asset_id(), u64::MAX);
	}

	#[test]
	fn test_to_domain_different_asset_ids() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let asset_ids = [0u64, 1, 10, 100, 999];
		for asset_id in asset_ids {
			let dto = NoteDto::new(100, asset_id, owner_pubkey, blinding);
			let note = dto.to_domain().unwrap();
			assert_eq!(note.asset_id(), asset_id);
		}
	}

	#[test]
	fn test_to_domain_all_zeros() {
		let dto = NoteDto::new(0, 0, [0u8; 32], [0u8; 32]);
		let result = dto.to_domain();
		assert!(result.is_ok());
	}

	#[test]
	fn test_to_domain_all_max() {
		let dto = NoteDto::new(u64::MAX, u64::MAX, [0xFFu8; 32], [0xFFu8; 32]);
		let result = dto.to_domain();
		assert!(result.is_ok());
	}

	// Roundtrip tests
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
	fn test_roundtrip_zero_values() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(0u64));
		let blinding = Blinding::from(Fr::from(0u64));
		let original_note = Note::new(0, 0, owner_pubkey, blinding);

		let dto = NoteDto::from_domain(&original_note);
		let converted_note = dto.to_domain().unwrap();

		assert_eq!(converted_note.value(), 0);
		assert_eq!(converted_note.asset_id(), 0);
	}

	#[test]
	fn test_roundtrip_large_values() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(999999u64));
		let blinding = Blinding::from(Fr::from(888888u64));
		let original_note = Note::new(u64::MAX, 12345, owner_pubkey, blinding);

		let dto = NoteDto::from_domain(&original_note);
		let converted_note = dto.to_domain().unwrap();

		assert_eq!(converted_note.value(), u64::MAX);
		assert_eq!(converted_note.asset_id(), 12345);
	}

	#[test]
	fn test_roundtrip_preserves_value() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));

		let values = [0u64, 1, 100, 1000, u64::MAX];
		for value in values {
			let original_note = Note::new(value, 0, owner_pubkey, blinding);
			let dto = NoteDto::from_domain(&original_note);
			let converted_note = dto.to_domain().unwrap();
			assert_eq!(converted_note.value(), value, "Failed for value {value}");
		}
	}

	#[test]
	fn test_roundtrip_preserves_asset_id() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));

		let asset_ids = [0u64, 1, 42, 999, u64::MAX];
		for asset_id in asset_ids {
			let original_note = Note::new(100, asset_id, owner_pubkey, blinding);
			let dto = NoteDto::from_domain(&original_note);
			let converted_note = dto.to_domain().unwrap();
			assert_eq!(
				converted_note.asset_id(),
				asset_id,
				"Failed for asset_id {asset_id}"
			);
		}
	}

	// field_to_bytes and bytes_to_field tests
	#[test]
	fn test_field_bytes_conversion_zero() {
		let field = Fr::from(0u64);
		let bytes = NoteDto::field_to_bytes(&field);
		let converted = NoteDto::bytes_to_field(&bytes).unwrap();
		assert_eq!(field, converted);
	}

	#[test]
	fn test_field_bytes_conversion_one() {
		let field = Fr::from(1u64);
		let bytes = NoteDto::field_to_bytes(&field);
		let converted = NoteDto::bytes_to_field(&bytes).unwrap();
		assert_eq!(field, converted);
	}

	#[test]
	fn test_field_bytes_conversion_large() {
		let field = Fr::from(u64::MAX);
		let bytes = NoteDto::field_to_bytes(&field);
		let converted = NoteDto::bytes_to_field(&bytes).unwrap();
		assert_eq!(field, converted);
	}

	#[test]
	fn test_field_bytes_conversion_random_values() {
		let values = [123u64, 456, 789, 999999, 1234567890];
		for value in values {
			let field = Fr::from(value);
			let bytes = NoteDto::field_to_bytes(&field);
			let converted = NoteDto::bytes_to_field(&bytes).unwrap();
			assert_eq!(field, converted, "Failed for value {value}");
		}
	}

	#[test]
	fn test_bytes_to_field_all_zeros() {
		let bytes = [0u8; 32];
		let field = NoteDto::bytes_to_field(&bytes).unwrap();
		assert_eq!(field, Fr::from(0u64));
	}

	#[test]
	fn test_bytes_to_field_all_ones() {
		let bytes = [1u8; 32];
		let field = NoteDto::bytes_to_field(&bytes);
		assert!(field.is_ok());
	}

	#[test]
	fn test_bytes_to_field_max_bytes() {
		let bytes = [0xFFu8; 32];
		let field = NoteDto::bytes_to_field(&bytes);
		assert!(field.is_ok());
	}

	// Clone and PartialEq tests
	#[test]
	fn test_clone() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];
		let dto = NoteDto::new(100, 0, owner_pubkey, blinding);

		let cloned = dto.clone();
		assert_eq!(dto, cloned);
	}

	#[test]
	fn test_dto_equality() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let dto1 = NoteDto::new(100, 0, owner_pubkey, blinding);
		let dto2 = NoteDto::new(100, 0, owner_pubkey, blinding);

		assert_eq!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_value() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let dto1 = NoteDto::new(100, 0, owner_pubkey, blinding);
		let dto2 = NoteDto::new(200, 0, owner_pubkey, blinding);

		assert_ne!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_asset_id() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		let dto1 = NoteDto::new(100, 0, owner_pubkey, blinding);
		let dto2 = NoteDto::new(100, 1, owner_pubkey, blinding);

		assert_ne!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_owner_pubkey() {
		let blinding = [2u8; 32];

		let dto1 = NoteDto::new(100, 0, [1u8; 32], blinding);
		let dto2 = NoteDto::new(100, 0, [99u8; 32], blinding);

		assert_ne!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_blinding() {
		let owner_pubkey = [1u8; 32];

		let dto1 = NoteDto::new(100, 0, owner_pubkey, [2u8; 32]);
		let dto2 = NoteDto::new(100, 0, owner_pubkey, [99u8; 32]);

		assert_ne!(dto1, dto2);
	}

	#[test]
	fn test_equality_all_zeros() {
		let dto1 = NoteDto::new(0, 0, [0u8; 32], [0u8; 32]);
		let dto2 = NoteDto::new(0, 0, [0u8; 32], [0u8; 32]);

		assert_eq!(dto1, dto2);
	}

	#[test]
	fn test_equality_all_max() {
		let dto1 = NoteDto::new(u64::MAX, u64::MAX, [0xFFu8; 32], [0xFFu8; 32]);
		let dto2 = NoteDto::new(u64::MAX, u64::MAX, [0xFFu8; 32], [0xFFu8; 32]);

		assert_eq!(dto1, dto2);
	}

	// Edge cases
	#[test]
	fn test_zero_value_note() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];
		let dto = NoteDto::new(0, 0, owner_pubkey, blinding);

		let note = dto.to_domain().unwrap();
		assert_eq!(note.value(), 0);
	}

	#[test]
	fn test_max_value_note() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];
		let dto = NoteDto::new(u64::MAX, 0, owner_pubkey, blinding);

		let note = dto.to_domain().unwrap();
		assert_eq!(note.value(), u64::MAX);
	}

	#[test]
	fn test_multiple_asset_ids() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		for asset_id in 0..10 {
			let dto = NoteDto::new(100, asset_id, owner_pubkey, blinding);
			let note = dto.to_domain().unwrap();
			assert_eq!(note.asset_id(), asset_id);
		}
	}

	#[test]
	fn test_consistent_bytes_representation() {
		let owner_pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 0, owner_pubkey, blinding);

		let dto1 = NoteDto::from_domain(&note);
		let dto2 = NoteDto::from_domain(&note);

		// Same note should produce identical DTOs
		assert_eq!(dto1, dto2);
		assert_eq!(dto1.owner_pubkey, dto2.owner_pubkey);
		assert_eq!(dto1.blinding, dto2.blinding);
	}

	// Debug trait test
	#[test]
	fn test_debug_format() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];
		let dto = NoteDto::new(100, 0, owner_pubkey, blinding);

		let debug_str = format!("{dto:?}");
		assert!(debug_str.contains("NoteDto"));
		assert!(debug_str.contains("value"));
	}

	// Serialization tests (only with std feature)
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

	#[cfg(feature = "std")]
	#[test]
	fn test_serialization_zero_values() {
		let dto = NoteDto::new(0, 0, [0u8; 32], [0u8; 32]);

		let json = serde_json::to_string(&dto).unwrap();
		let deserialized: NoteDto = serde_json::from_str(&json).unwrap();

		assert_eq!(dto, deserialized);
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_serialization_large_values() {
		let dto = NoteDto::new(u64::MAX, u64::MAX, [0xFFu8; 32], [0xFFu8; 32]);

		let json = serde_json::to_string(&dto).unwrap();
		let deserialized: NoteDto = serde_json::from_str(&json).unwrap();

		assert_eq!(dto, deserialized);
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_serialization_different_asset_ids() {
		let owner_pubkey = [1u8; 32];
		let blinding = [2u8; 32];

		for asset_id in [0, 1, 42, 999] {
			let dto = NoteDto::new(100, asset_id, owner_pubkey, blinding);
			let json = serde_json::to_string(&dto).unwrap();
			let deserialized: NoteDto = serde_json::from_str(&json).unwrap();
			assert_eq!(dto, deserialized);
		}
	}
}
