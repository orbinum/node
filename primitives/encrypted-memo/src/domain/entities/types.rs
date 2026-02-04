//! Core Types
//!
//! MemoData, ViewingKey, NullifierKey, EdDSAKey.

use super::error::MemoError;
#[cfg(feature = "parity-scale-codec")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "scale-info")]
use scale_info::TypeInfo;

/// Plaintext memo data
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct MemoData {
	/// The value/amount in the note
	pub value: u64,
	/// Owner's public key (32 bytes)
	pub owner_pk: [u8; 32],
	/// Random blinding factor (32 bytes)
	pub blinding: [u8; 32],
	/// Asset identifier (0 = native token)
	pub asset_id: u32,
}

impl MemoData {
	/// Create new memo data
	pub fn new(value: u64, owner_pk: [u8; 32], blinding: [u8; 32], asset_id: u32) -> Self {
		Self {
			value,
			owner_pk,
			blinding,
			asset_id,
		}
	}

	/// Serializes to bytes (76 bytes: 8+32+32+4)
	pub fn to_bytes(&self) -> [u8; 76] {
		let mut bytes = [0u8; 76];
		bytes[0..8].copy_from_slice(&self.value.to_le_bytes());
		bytes[8..40].copy_from_slice(&self.owner_pk);
		bytes[40..72].copy_from_slice(&self.blinding);
		bytes[72..76].copy_from_slice(&self.asset_id.to_le_bytes());
		bytes
	}

	/// Deserializes from bytes
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() != 76 {
			return Err(MemoError::InvalidNoteData);
		}

		let value = u64::from_le_bytes(
			bytes[0..8]
				.try_into()
				.map_err(|_| MemoError::InvalidNoteData)?,
		);

		let mut owner_pk = [0u8; 32];
		owner_pk.copy_from_slice(&bytes[8..40]);

		let mut blinding = [0u8; 32];
		blinding.copy_from_slice(&bytes[40..72]);

		let asset_id = u32::from_le_bytes(
			bytes[72..76]
				.try_into()
				.map_err(|_| MemoError::InvalidNoteData)?,
		);

		Ok(Self {
			value,
			owner_pk,
			blinding,
			asset_id,
		})
	}
}

/// Viewing key for memo decryption
///
/// Read-only access, shareable with auditors.
/// Derived: SHA256(spending_key || "orbinum-viewing-key-v1")
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct ViewingKey(pub [u8; 32]);

impl ViewingKey {
	/// Creates viewing key from raw bytes
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Get raw bytes
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl AsRef<[u8; 32]> for ViewingKey {
	fn as_ref(&self) -> &[u8; 32] {
		&self.0
	}
}

impl From<[u8; 32]> for ViewingKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
}

/// Nullifier derivation key
///
/// Used to derive nullifiers for spent notes.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct NullifierKey(pub [u8; 32]);

impl NullifierKey {
	/// Creates nullifier key from raw bytes
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns raw bytes
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl AsRef<[u8; 32]> for NullifierKey {
	fn as_ref(&self) -> &[u8; 32] {
		&self.0
	}
}

impl From<[u8; 32]> for NullifierKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
}

/// EdDSA signing key for circuit ownership proofs
///
/// BabyJubJub curve, circom-compatible.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct EdDSAKey(pub [u8; 32]);

impl EdDSAKey {
	/// Creates EdDSA key from raw bytes
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns raw bytes
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl AsRef<[u8; 32]> for EdDSAKey {
	fn as_ref(&self) -> &[u8; 32] {
		&self.0
	}
}

impl From<[u8; 32]> for EdDSAKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::vec;

	// ===== MemoData Tests =====

	#[test]
	fn test_memo_data_new() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);

		assert_eq!(memo.value, 1000);
		assert_eq!(memo.owner_pk, [1u8; 32]);
		assert_eq!(memo.blinding, [2u8; 32]);
		assert_eq!(memo.asset_id, 0);
	}

	#[test]
	fn test_memo_data_new_zero_value() {
		let memo = MemoData::new(0, [0u8; 32], [0u8; 32], 0);

		assert_eq!(memo.value, 0);
		assert_eq!(memo.owner_pk, [0u8; 32]);
		assert_eq!(memo.blinding, [0u8; 32]);
		assert_eq!(memo.asset_id, 0);
	}

	#[test]
	fn test_memo_data_new_max_value() {
		let memo = MemoData::new(u64::MAX, [255u8; 32], [128u8; 32], u32::MAX);

		assert_eq!(memo.value, u64::MAX);
		assert_eq!(memo.owner_pk, [255u8; 32]);
		assert_eq!(memo.blinding, [128u8; 32]);
		assert_eq!(memo.asset_id, u32::MAX);
	}

	#[test]
	fn test_memo_data_to_bytes() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 5);
		let bytes = memo.to_bytes();

		assert_eq!(bytes.len(), 76);
		// Check value (little-endian)
		assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1000);
		// Check owner_pk
		assert_eq!(&bytes[8..40], &[1u8; 32]);
		// Check blinding
		assert_eq!(&bytes[40..72], &[2u8; 32]);
		// Check asset_id
		assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 5);
	}

	#[test]
	fn test_memo_data_from_bytes() {
		let original = MemoData::new(500, [10u8; 32], [20u8; 32], 3);
		let bytes = original.to_bytes();
		let recovered = MemoData::from_bytes(&bytes).unwrap();

		assert_eq!(recovered, original);
	}

	#[test]
	fn test_memo_data_from_bytes_roundtrip() {
		let test_cases = vec![
			MemoData::new(0, [0u8; 32], [0u8; 32], 0),
			MemoData::new(1, [1u8; 32], [1u8; 32], 1),
			MemoData::new(u64::MAX, [255u8; 32], [255u8; 32], u32::MAX),
			MemoData::new(12345, [42u8; 32], [99u8; 32], 7),
		];

		for original in test_cases {
			let bytes = original.to_bytes();
			let recovered = MemoData::from_bytes(&bytes).unwrap();
			assert_eq!(recovered, original);
		}
	}

	#[test]
	fn test_memo_data_from_bytes_invalid_length() {
		let result = MemoData::from_bytes(&[0u8; 75]);
		assert!(result.is_err());

		let result = MemoData::from_bytes(&[0u8; 77]);
		assert!(result.is_err());

		let result = MemoData::from_bytes(&[]);
		assert!(result.is_err());
	}

	#[test]
	fn test_memo_data_clone() {
		let memo1 = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let memo2 = memo1.clone();

		assert_eq!(memo1, memo2);
	}

	#[test]
	fn test_memo_data_partial_eq() {
		let memo1 = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let memo2 = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let memo3 = MemoData::new(500, [1u8; 32], [2u8; 32], 0);

		assert_eq!(memo1, memo2);
		assert_ne!(memo1, memo3);
	}

	// ===== ViewingKey Tests =====

	#[test]
	fn test_viewing_key_from_bytes() {
		let bytes = [42u8; 32];
		let vk = ViewingKey::from_bytes(bytes);

		assert_eq!(vk.as_bytes(), &bytes);
	}

	#[test]
	fn test_viewing_key_as_bytes() {
		let bytes = [1u8; 32];
		let vk = ViewingKey::from_bytes(bytes);

		assert_eq!(vk.as_bytes(), &bytes);
		assert_eq!(*vk.as_bytes(), bytes);
	}

	#[test]
	fn test_viewing_key_as_ref() {
		let bytes = [10u8; 32];
		let vk = ViewingKey::from_bytes(bytes);
		let as_ref: &[u8; 32] = vk.as_ref();

		assert_eq!(as_ref, &bytes);
	}

	#[test]
	fn test_viewing_key_from() {
		let bytes = [99u8; 32];
		let vk: ViewingKey = bytes.into();

		assert_eq!(vk.as_bytes(), &bytes);
	}

	#[test]
	fn test_viewing_key_clone() {
		let vk1 = ViewingKey::from_bytes([5u8; 32]);
		let vk2 = vk1.clone();

		assert_eq!(vk1, vk2);
	}

	#[test]
	fn test_viewing_key_partial_eq() {
		let vk1 = ViewingKey::from_bytes([1u8; 32]);
		let vk2 = ViewingKey::from_bytes([1u8; 32]);
		let vk3 = ViewingKey::from_bytes([2u8; 32]);

		assert_eq!(vk1, vk2);
		assert_ne!(vk1, vk3);
	}

	#[test]
	fn test_viewing_key_zero() {
		let vk = ViewingKey::from_bytes([0u8; 32]);
		assert_eq!(vk.as_bytes(), &[0u8; 32]);
	}

	#[test]
	fn test_viewing_key_max() {
		let vk = ViewingKey::from_bytes([255u8; 32]);
		assert_eq!(vk.as_bytes(), &[255u8; 32]);
	}

	// ===== NullifierKey Tests =====

	#[test]
	fn test_nullifier_key_from_bytes() {
		let bytes = [42u8; 32];
		let nk = NullifierKey::from_bytes(bytes);

		assert_eq!(nk.as_bytes(), &bytes);
	}

	#[test]
	fn test_nullifier_key_as_bytes() {
		let bytes = [1u8; 32];
		let nk = NullifierKey::from_bytes(bytes);

		assert_eq!(nk.as_bytes(), &bytes);
		assert_eq!(*nk.as_bytes(), bytes);
	}

	#[test]
	fn test_nullifier_key_as_ref() {
		let bytes = [10u8; 32];
		let nk = NullifierKey::from_bytes(bytes);
		let as_ref: &[u8; 32] = nk.as_ref();

		assert_eq!(as_ref, &bytes);
	}

	#[test]
	fn test_nullifier_key_from() {
		let bytes = [99u8; 32];
		let nk: NullifierKey = bytes.into();

		assert_eq!(nk.as_bytes(), &bytes);
	}

	#[test]
	fn test_nullifier_key_clone() {
		let nk1 = NullifierKey::from_bytes([5u8; 32]);
		let nk2 = nk1.clone();

		assert_eq!(nk1, nk2);
	}

	#[test]
	fn test_nullifier_key_partial_eq() {
		let nk1 = NullifierKey::from_bytes([1u8; 32]);
		let nk2 = NullifierKey::from_bytes([1u8; 32]);
		let nk3 = NullifierKey::from_bytes([2u8; 32]);

		assert_eq!(nk1, nk2);
		assert_ne!(nk1, nk3);
	}

	#[test]
	fn test_nullifier_key_zero() {
		let nk = NullifierKey::from_bytes([0u8; 32]);
		assert_eq!(nk.as_bytes(), &[0u8; 32]);
	}

	#[test]
	fn test_nullifier_key_max() {
		let nk = NullifierKey::from_bytes([255u8; 32]);
		assert_eq!(nk.as_bytes(), &[255u8; 32]);
	}

	// ===== EdDSAKey Tests =====

	#[test]
	fn test_eddsa_key_from_bytes() {
		let bytes = [42u8; 32];
		let ek = EdDSAKey::from_bytes(bytes);

		assert_eq!(ek.as_bytes(), &bytes);
	}

	#[test]
	fn test_eddsa_key_as_bytes() {
		let bytes = [1u8; 32];
		let ek = EdDSAKey::from_bytes(bytes);

		assert_eq!(ek.as_bytes(), &bytes);
		assert_eq!(*ek.as_bytes(), bytes);
	}

	#[test]
	fn test_eddsa_key_as_ref() {
		let bytes = [10u8; 32];
		let ek = EdDSAKey::from_bytes(bytes);
		let as_ref: &[u8; 32] = ek.as_ref();

		assert_eq!(as_ref, &bytes);
	}

	#[test]
	fn test_eddsa_key_from() {
		let bytes = [99u8; 32];
		let ek: EdDSAKey = bytes.into();

		assert_eq!(ek.as_bytes(), &bytes);
	}

	#[test]
	fn test_eddsa_key_clone() {
		let ek1 = EdDSAKey::from_bytes([5u8; 32]);
		let ek2 = ek1.clone();

		assert_eq!(ek1, ek2);
	}

	#[test]
	fn test_eddsa_key_partial_eq() {
		let ek1 = EdDSAKey::from_bytes([1u8; 32]);
		let ek2 = EdDSAKey::from_bytes([1u8; 32]);
		let ek3 = EdDSAKey::from_bytes([2u8; 32]);

		assert_eq!(ek1, ek2);
		assert_ne!(ek1, ek3);
	}

	#[test]
	fn test_eddsa_key_zero() {
		let ek = EdDSAKey::from_bytes([0u8; 32]);
		assert_eq!(ek.as_bytes(), &[0u8; 32]);
	}

	#[test]
	fn test_eddsa_key_max() {
		let ek = EdDSAKey::from_bytes([255u8; 32]);
		assert_eq!(ek.as_bytes(), &[255u8; 32]);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_all_keys_distinct() {
		let bytes = [42u8; 32];
		let vk = ViewingKey::from_bytes(bytes);
		let nk = NullifierKey::from_bytes(bytes);
		let ek = EdDSAKey::from_bytes(bytes);

		// All should have same bytes but be different types
		assert_eq!(vk.as_bytes(), &bytes);
		assert_eq!(nk.as_bytes(), &bytes);
		assert_eq!(ek.as_bytes(), &bytes);
	}

	#[test]
	fn test_memo_data_serialization_consistency() {
		for i in 0..10u64 {
			let memo = MemoData::new(i * 100, [i as u8; 32], [(i * 2) as u8; 32], i as u32);
			let bytes = memo.to_bytes();
			let recovered = MemoData::from_bytes(&bytes).unwrap();
			assert_eq!(memo, recovered);
		}
	}

	#[test]
	fn test_key_types_conversion() {
		let bytes = [123u8; 32];

		// Test From trait
		let vk: ViewingKey = bytes.into();
		let nk: NullifierKey = bytes.into();
		let ek: EdDSAKey = bytes.into();

		// Test AsRef trait
		let vk_ref: &[u8; 32] = vk.as_ref();
		let nk_ref: &[u8; 32] = nk.as_ref();
		let ek_ref: &[u8; 32] = ek.as_ref();

		assert_eq!(vk_ref, &bytes);
		assert_eq!(nk_ref, &bytes);
		assert_eq!(ek_ref, &bytes);
	}
}
