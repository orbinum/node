//! Partial Memo Data.
//!
//! Selectively revealed note fields. Only disclosed fields are `Some`.

use alloc::vec::Vec;

use crate::domain::entities::{error::MemoError, memo_data::MemoData};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use scale_info::TypeInfo;

use super::mask::DisclosureMask;

/// Partially revealed memo data.
///
/// Each `Option` field is `Some` only when the corresponding bit in the
/// disclosure mask is set.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct PartialMemoData {
	/// Revealed token amount (`None` when not disclosed)
	pub value: Option<u64>,
	/// Revealed owner public key (`None` when not disclosed)
	pub owner_pk: Option<[u8; 32]>,
	/// Revealed blinding factor — should normally be `None`
	pub blinding: Option<[u8; 32]>,
	/// Revealed asset ID (`None` when not disclosed)
	pub asset_id: Option<u32>,
}

impl PartialMemoData {
	/// Creates an empty partial memo (nothing revealed).
	pub fn empty() -> Self {
		Self {
			value: None,
			owner_pk: None,
			blinding: None,
			asset_id: None,
		}
	}

	/// Creates partial memo by applying a disclosure mask to complete memo data.
	pub fn from_disclosure(memo: &MemoData, mask: &DisclosureMask) -> Self {
		Self {
			value: if mask.disclose_value {
				Some(memo.value)
			} else {
				None
			},
			owner_pk: if mask.disclose_owner {
				Some(memo.owner_pk)
			} else {
				None
			},
			blinding: if mask.disclose_blinding {
				Some(memo.blinding)
			} else {
				None
			},
			asset_id: if mask.disclose_asset_id {
				Some(memo.asset_id)
			} else {
				None
			},
		}
	}

	/// Returns `true` when no fields are revealed.
	pub fn is_empty(&self) -> bool {
		self.value.is_none()
			&& self.owner_pk.is_none()
			&& self.blinding.is_none()
			&& self.asset_id.is_none()
	}

	/// Serializes to bytes: `flags(1) || [optional fields...]`.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		let flags = (self.value.is_some() as u8)
			| (self.owner_pk.is_some() as u8) << 1
			| (self.blinding.is_some() as u8) << 2
			| (self.asset_id.is_some() as u8) << 3;
		bytes.push(flags);
		if let Some(v) = self.value {
			bytes.extend_from_slice(&v.to_le_bytes());
		}
		if let Some(pk) = self.owner_pk {
			bytes.extend_from_slice(&pk);
		}
		if let Some(b) = self.blinding {
			bytes.extend_from_slice(&b);
		}
		if let Some(id) = self.asset_id {
			bytes.extend_from_slice(&id.to_le_bytes());
		}
		bytes
	}

	/// Deserializes from bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.is_empty() {
			return Err(MemoError::InvalidDisclosureData);
		}
		let flags = bytes[0];
		let mut off = 1;

		let value = if (flags & 0b0001) != 0 {
			if bytes.len() < off + 8 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let v = u64::from_le_bytes(
				bytes[off..off + 8]
					.try_into()
					.map_err(|_| MemoError::InvalidDisclosureData)?,
			);
			off += 8;
			Some(v)
		} else {
			None
		};

		let owner_pk = if (flags & 0b0010) != 0 {
			if bytes.len() < off + 32 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let mut pk = [0u8; 32];
			pk.copy_from_slice(&bytes[off..off + 32]);
			off += 32;
			Some(pk)
		} else {
			None
		};

		let blinding = if (flags & 0b0100) != 0 {
			if bytes.len() < off + 32 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let mut b = [0u8; 32];
			b.copy_from_slice(&bytes[off..off + 32]);
			off += 32;
			Some(b)
		} else {
			None
		};

		let asset_id = if (flags & 0b1000) != 0 {
			if bytes.len() < off + 4 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let id = u32::from_le_bytes(
				bytes[off..off + 4]
					.try_into()
					.map_err(|_| MemoError::InvalidDisclosureData)?,
			);
			Some(id)
		} else {
			None
		};

		Ok(Self {
			value,
			owner_pk,
			blinding,
			asset_id,
		})
	}

	/// Validates that at least one field is revealed.
	pub fn validate(&self) -> Result<(), MemoError> {
		if self.is_empty() {
			return Err(MemoError::InvalidDisclosureData);
		}
		Ok(())
	}
}

impl Default for PartialMemoData {
	fn default() -> Self {
		Self::empty()
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;

	#[test]
	fn test_partial_empty() {
		let p = PartialMemoData::empty();
		assert!(p.is_empty());
	}

	#[test]
	fn test_partial_from_disclosure_value_only() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let p = PartialMemoData::from_disclosure(&memo, &DisclosureMask::only_value());
		assert_eq!(p.value, Some(1000));
		assert!(p.owner_pk.is_none());
		assert!(p.asset_id.is_none());
	}

	#[test]
	fn test_partial_from_disclosure_all() {
		let memo = MemoData::new(500, [5u8; 32], [10u8; 32], 2);
		let p = PartialMemoData::from_disclosure(&memo, &DisclosureMask::all());
		assert_eq!(p.value, Some(500));
		assert_eq!(p.owner_pk, Some([5u8; 32]));
		assert!(p.blinding.is_none()); // all() keeps blinding false
		assert_eq!(p.asset_id, Some(2));
	}

	#[test]
	fn test_partial_to_bytes_value_only() {
		let p = PartialMemoData {
			value: Some(1000),
			owner_pk: None,
			blinding: None,
			asset_id: None,
		};
		let bytes = p.to_bytes();
		assert_eq!(bytes[0], 0b0001);
		assert_eq!(bytes.len(), 9); // 1 flag + 8 value
	}

	#[test]
	fn test_partial_roundtrip() {
		let original = PartialMemoData {
			value: Some(500),
			owner_pk: Some([5u8; 32]),
			blinding: None,
			asset_id: Some(2),
		};
		let recovered = PartialMemoData::from_bytes(&original.to_bytes()).unwrap();
		assert_eq!(recovered, original);
	}

	#[test]
	fn test_partial_from_bytes_empty_error() {
		assert!(PartialMemoData::from_bytes(&[]).is_err());
	}

	#[test]
	fn test_partial_from_bytes_truncated_error() {
		assert!(PartialMemoData::from_bytes(&[0b0001]).is_err());
	}

	#[test]
	fn test_partial_validate_ok() {
		let p = PartialMemoData {
			value: Some(100),
			..PartialMemoData::empty()
		};
		assert!(p.validate().is_ok());
	}

	#[test]
	fn test_partial_validate_empty_error() {
		assert!(PartialMemoData::empty().validate().is_err());
	}

	#[test]
	fn test_partial_default() {
		assert!(PartialMemoData::default().is_empty());
	}

	#[test]
	fn test_partial_is_empty_false_when_has_field() {
		let p = PartialMemoData {
			value: Some(1),
			..PartialMemoData::empty()
		};
		assert!(!p.is_empty());
		let p2 = PartialMemoData {
			asset_id: Some(3),
			..PartialMemoData::empty()
		};
		assert!(!p2.is_empty());
	}

	#[test]
	fn test_partial_from_disclosure_value_and_asset() {
		let memo = MemoData::new(500, [5u8; 32], [10u8; 32], 7);
		let p = PartialMemoData::from_disclosure(&memo, &DisclosureMask::value_and_asset());
		assert_eq!(p.value, Some(500));
		assert_eq!(p.asset_id, Some(7));
		assert!(p.owner_pk.is_none());
		assert!(p.blinding.is_none());
	}

	#[test]
	fn test_partial_to_bytes_all_fields() {
		let p = PartialMemoData {
			value: Some(500),
			owner_pk: Some([5u8; 32]),
			blinding: Some([10u8; 32]),
			asset_id: Some(2),
		};
		let bytes = p.to_bytes();
		// 1 (flags) + 8 (value) + 32 (owner_pk) + 32 (blinding) + 4 (asset_id)
		assert_eq!(bytes[0], 0b1111);
		assert_eq!(bytes.len(), 77);
	}

	#[test]
	fn test_partial_roundtrip_all_fields() {
		let original = PartialMemoData {
			value: Some(9999),
			owner_pk: Some([0xAAu8; 32]),
			blinding: Some([0xBBu8; 32]),
			asset_id: Some(42),
		};
		let recovered = PartialMemoData::from_bytes(&original.to_bytes()).unwrap();
		assert_eq!(recovered, original);
	}

	#[test]
	fn test_partial_clone() {
		let p1 = PartialMemoData {
			value: Some(100),
			..PartialMemoData::empty()
		};
		let p2 = p1.clone();
		assert_eq!(p1, p2);
	}
}
