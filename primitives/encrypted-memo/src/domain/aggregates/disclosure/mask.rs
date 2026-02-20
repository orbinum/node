//! Disclosure Mask value object.
//!
//! Controls which note fields are revealed in a selective disclosure proof.

use crate::domain::entities::error::MemoError;
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use scale_info::TypeInfo;

/// Disclosure mask defining which memo fields to reveal.
///
/// The `disclose_blinding` flag MUST always remain `false` to preserve
/// commitment privacy.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosureMask {
	/// Reveal the token amount
	pub disclose_value: bool,
	/// Reveal the owner public key (or its hash)
	pub disclose_owner: bool,
	/// Reveal the blinding factor — MUST ALWAYS BE FALSE
	pub disclose_blinding: bool,
	/// Reveal the asset ID
	pub disclose_asset_id: bool,
}

impl DisclosureMask {
	/// Reveals all fields except `blinding`.
	pub fn all() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: true,
			disclose_blinding: false, // NEVER reveal blinding
			disclose_asset_id: true,
		}
	}

	/// Reveals only the token amount.
	pub fn only_value() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: false,
		}
	}

	/// Reveals the token amount and the asset ID.
	pub fn value_and_asset() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: true,
		}
	}

	/// Reveals nothing (invalid for a proof — use for constructing custom masks).
	pub fn none() -> Self {
		Self {
			disclose_value: false,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: false,
		}
	}

	/// Converts the mask to a 4-bit bitmap for circuit encoding.
	///
	/// Bit layout: `[asset_id | blinding | owner | value]` (LSB first)
	pub fn to_bitmap(&self) -> u8 {
		(self.disclose_value as u8)
			| (self.disclose_owner as u8) << 1
			| (self.disclose_blinding as u8) << 2
			| (self.disclose_asset_id as u8) << 3
	}

	/// Creates a mask from a 4-bit bitmap (inverse of [`to_bitmap`]).
	pub fn from_bitmap(bits: u8) -> Self {
		Self {
			disclose_value: (bits & 0b0001) != 0,
			disclose_owner: (bits & 0b0010) != 0,
			disclose_blinding: (bits & 0b0100) != 0,
			disclose_asset_id: (bits & 0b1000) != 0,
		}
	}

	/// Validates mask safety rules:
	/// - `disclose_blinding` must be `false`
	/// - At least one field must be revealed
	pub fn validate(&self) -> Result<(), MemoError> {
		if self.disclose_blinding {
			return Err(MemoError::InvalidDisclosureMask(
				"Cannot disclose blinding factor — compromises commitment privacy",
			));
		}
		if !self.disclose_value && !self.disclose_owner && !self.disclose_asset_id {
			return Err(MemoError::InvalidDisclosureMask(
				"Must disclose at least one field (value, owner, or asset_id)",
			));
		}
		Ok(())
	}

	/// Returns the number of fields that will be revealed.
	pub fn disclosed_field_count(&self) -> usize {
		[
			self.disclose_value,
			self.disclose_owner,
			self.disclose_blinding,
			self.disclose_asset_id,
		]
		.iter()
		.filter(|&&v| v)
		.count()
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_mask_all() {
		let mask = DisclosureMask::all();
		assert!(mask.disclose_value);
		assert!(mask.disclose_owner);
		assert!(!mask.disclose_blinding);
		assert!(mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_only_value() {
		let mask = DisclosureMask::only_value();
		assert!(mask.disclose_value);
		assert!(!mask.disclose_owner);
		assert!(!mask.disclose_blinding);
		assert!(!mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_value_and_asset() {
		let mask = DisclosureMask::value_and_asset();
		assert!(mask.disclose_value);
		assert!(!mask.disclose_owner);
		assert!(!mask.disclose_blinding);
		assert!(mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_none() {
		let mask = DisclosureMask::none();
		assert!(!mask.disclose_value);
		assert!(!mask.disclose_owner);
		assert!(!mask.disclose_blinding);
		assert!(!mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_to_bitmap() {
		assert_eq!(DisclosureMask::only_value().to_bitmap(), 0b0001);
		assert_eq!(DisclosureMask::value_and_asset().to_bitmap(), 0b1001);
		assert_eq!(DisclosureMask::all().to_bitmap(), 0b1011);
		assert_eq!(DisclosureMask::none().to_bitmap(), 0b0000);
	}

	#[test]
	fn test_mask_bitmap_roundtrip() {
		for i in 0..16u8 {
			let mask = DisclosureMask::from_bitmap(i);
			assert_eq!(mask.to_bitmap(), i);
		}
	}

	#[test]
	fn test_mask_validate_ok() {
		assert!(DisclosureMask::only_value().validate().is_ok());
		assert!(DisclosureMask::all().validate().is_ok());
		assert!(DisclosureMask::value_and_asset().validate().is_ok());
	}

	#[test]
	fn test_mask_validate_blinding_error() {
		let mask = DisclosureMask {
			disclose_blinding: true,
			..DisclosureMask::only_value()
		};
		assert!(mask.validate().is_err());
	}

	#[test]
	fn test_mask_validate_empty_error() {
		assert!(DisclosureMask::none().validate().is_err());
	}

	#[test]
	fn test_mask_disclosed_field_count() {
		assert_eq!(DisclosureMask::none().disclosed_field_count(), 0);
		assert_eq!(DisclosureMask::only_value().disclosed_field_count(), 1);
		assert_eq!(DisclosureMask::value_and_asset().disclosed_field_count(), 2);
		assert_eq!(DisclosureMask::all().disclosed_field_count(), 3);
	}

	#[test]
	fn test_mask_clone() {
		let m1 = DisclosureMask::value_and_asset();
		let m2 = m1.clone();
		assert_eq!(m1, m2);
	}

	#[test]
	fn test_mask_from_bitmap_specific_values() {
		// Bit layout: asset_id(3) | blinding(2) | owner(1) | value(0)
		let owner_only = DisclosureMask::from_bitmap(0b0010);
		assert!(!owner_only.disclose_value);
		assert!(owner_only.disclose_owner);
		assert!(!owner_only.disclose_blinding);
		assert!(!owner_only.disclose_asset_id);
	}

	#[test]
	fn test_mask_validate_only_owner() {
		let mask = DisclosureMask::from_bitmap(0b0010); // owner only
		assert!(mask.validate().is_ok());
	}
}
