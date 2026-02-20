//! MemoData entity.
//!
//! Plaintext content of an encrypted note memo.

use super::error::MemoError;
use crate::domain::value_objects::constants::{MAX_ENCRYPTED_MEMO_SIZE, MIN_ENCRYPTED_MEMO_SIZE};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use scale_info::TypeInfo;

/// Plaintext memo data carried inside an encrypted note.
///
/// Serialized layout (76 bytes):
/// `value(8) || owner_pk(32) || blinding(32) || asset_id(4)`
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct MemoData {
	/// Token amount in the note
	pub value: u64,
	/// Owner's public key (32 bytes)
	pub owner_pk: [u8; 32],
	/// Random blinding factor (32 bytes)
	pub blinding: [u8; 32],
	/// Asset identifier (0 = native token)
	pub asset_id: u32,
}

impl MemoData {
	/// Creates new memo data.
	pub fn new(value: u64, owner_pk: [u8; 32], blinding: [u8; 32], asset_id: u32) -> Self {
		Self {
			value,
			owner_pk,
			blinding,
			asset_id,
		}
	}

	/// Serializes to bytes (76 bytes: 8+32+32+4).
	pub fn to_bytes(&self) -> [u8; 76] {
		let mut bytes = [0u8; 76];
		bytes[0..8].copy_from_slice(&self.value.to_le_bytes());
		bytes[8..40].copy_from_slice(&self.owner_pk);
		bytes[40..72].copy_from_slice(&self.blinding);
		bytes[72..76].copy_from_slice(&self.asset_id.to_le_bytes());
		bytes
	}

	/// Deserializes from bytes.
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

/// Returns true when `data` has a valid encrypted memo length (28-104 bytes).
///
/// Valid range: `nonce(12) + MAC(16)` minimum up to `nonce(12) + plaintext(76) + MAC(16)`.
pub fn is_valid_encrypted_memo(data: &[u8]) -> bool {
	(MIN_ENCRYPTED_MEMO_SIZE..=MAX_ENCRYPTED_MEMO_SIZE).contains(&data.len())
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
	}

	#[test]
	fn test_memo_data_new_max_value() {
		let memo = MemoData::new(u64::MAX, [255u8; 32], [128u8; 32], u32::MAX);
		assert_eq!(memo.value, u64::MAX);
		assert_eq!(memo.asset_id, u32::MAX);
	}

	#[test]
	fn test_memo_data_to_bytes() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 5);
		let bytes = memo.to_bytes();
		assert_eq!(bytes.len(), 76);
		assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1000);
		assert_eq!(&bytes[8..40], &[1u8; 32]);
		assert_eq!(&bytes[40..72], &[2u8; 32]);
		assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 5);
	}

	#[test]
	fn test_memo_data_from_bytes_roundtrip() {
		let original = MemoData::new(500, [10u8; 32], [20u8; 32], 3);
		let bytes = original.to_bytes();
		let recovered = MemoData::from_bytes(&bytes).unwrap();
		assert_eq!(recovered, original);
	}

	#[test]
	fn test_memo_data_from_bytes_wrong_length() {
		assert!(MemoData::from_bytes(&[0u8; 50]).is_err());
		assert!(MemoData::from_bytes(&[0u8; 77]).is_err());
		assert!(MemoData::from_bytes(&[]).is_err());
	}

	// ===== is_valid_encrypted_memo Tests =====

	#[test]
	fn test_valid_min_size() {
		assert!(is_valid_encrypted_memo(&vec![0u8; MIN_ENCRYPTED_MEMO_SIZE]));
	}

	#[test]
	fn test_valid_max_size() {
		assert!(is_valid_encrypted_memo(&vec![0u8; MAX_ENCRYPTED_MEMO_SIZE]));
	}

	#[test]
	fn test_invalid_too_short() {
		assert!(!is_valid_encrypted_memo(&vec![
			0u8;
			MIN_ENCRYPTED_MEMO_SIZE - 1
		]));
	}

	#[test]
	fn test_invalid_too_long() {
		assert!(!is_valid_encrypted_memo(&vec![
			0u8;
			MAX_ENCRYPTED_MEMO_SIZE + 1
		]));
	}

	#[test]
	fn test_invalid_empty() {
		assert!(!is_valid_encrypted_memo(&[]));
	}

	#[test]
	fn test_boundary_just_below_min() {
		assert!(!is_valid_encrypted_memo(&vec![0u8; 27]));
	}

	#[test]
	fn test_boundary_just_above_max() {
		assert!(!is_valid_encrypted_memo(&vec![0u8; 105]));
	}

	#[test]
	fn test_valid_mid_size() {
		assert!(is_valid_encrypted_memo(&vec![0u8; 60]));
	}

	#[test]
	fn test_memo_data_clone() {
		let m1 = MemoData::new(42, [3u8; 32], [7u8; 32], 1);
		let m2 = m1.clone();
		assert_eq!(m1, m2);
	}

	#[test]
	fn test_memo_data_eq_ne() {
		let m1 = MemoData::new(1, [0u8; 32], [0u8; 32], 0);
		let m2 = MemoData::new(1, [0u8; 32], [0u8; 32], 0);
		let m3 = MemoData::new(2, [0u8; 32], [0u8; 32], 0);
		assert_eq!(m1, m2);
		assert_ne!(m1, m3);
	}

	#[test]
	fn test_memo_data_from_bytes_all_zeros() {
		let bytes = [0u8; 76];
		let memo = MemoData::from_bytes(&bytes).unwrap();
		assert_eq!(memo.value, 0);
		assert_eq!(memo.asset_id, 0);
		assert_eq!(memo.owner_pk, [0u8; 32]);
		assert_eq!(memo.blinding, [0u8; 32]);
	}

	#[test]
	fn test_memo_data_to_bytes_field_layout() {
		// Verifica la posición exacta de cada campo en el serializado
		let memo = MemoData::new(u64::MAX, [0xAAu8; 32], [0xBBu8; 32], u32::MAX);
		let b = memo.to_bytes();
		assert_eq!(b[0..8], u64::MAX.to_le_bytes());
		assert_eq!(b[8..40], [0xAAu8; 32]);
		assert_eq!(b[40..72], [0xBBu8; 32]);
		assert_eq!(b[72..76], u32::MAX.to_le_bytes());
	}
}
