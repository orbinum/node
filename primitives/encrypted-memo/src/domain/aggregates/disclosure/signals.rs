//! Disclosure Public Signals.
//!
//! On-chain verified output of the disclosure circuit.

use crate::domain::entities::error::MemoError;
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use scale_info::TypeInfo;

use super::mask::DisclosureMask;

/// Public signals produced by the disclosure circuit and verified on-chain.
///
/// Fixed serialized size: 76 bytes (`commitment(32) + value(8) + asset_id(4) + owner_hash(32)`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosurePublicSignals {
	/// Commitment binding the proof to a specific note
	pub commitment: [u8; 32],
	/// Revealed token amount (0 when not disclosed)
	pub revealed_value: u64,
	/// Revealed asset ID (0 when not disclosed)
	pub revealed_asset_id: u32,
	/// Hash of owner public key (zero when owner not disclosed)
	pub revealed_owner_hash: [u8; 32],
}

impl DisclosurePublicSignals {
	/// Creates new public signals.
	pub fn new(
		commitment: [u8; 32],
		revealed_value: u64,
		revealed_asset_id: u32,
		revealed_owner_hash: [u8; 32],
	) -> Self {
		Self {
			commitment,
			revealed_value,
			revealed_asset_id,
			revealed_owner_hash,
		}
	}

	/// Serializes to bytes (fixed 76 bytes).
	pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
		let mut bytes = alloc::vec::Vec::with_capacity(76);
		bytes.extend_from_slice(&self.commitment);
		bytes.extend_from_slice(&self.revealed_value.to_le_bytes());
		bytes.extend_from_slice(&self.revealed_asset_id.to_le_bytes());
		bytes.extend_from_slice(&self.revealed_owner_hash);
		bytes
	}

	/// Deserializes from bytes (must be exactly 76 bytes).
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() != 76 {
			return Err(MemoError::InvalidProof("Invalid public signals length"));
		}
		let mut commitment = [0u8; 32];
		commitment.copy_from_slice(&bytes[0..32]);

		let revealed_value = u64::from_le_bytes(
			bytes[32..40]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid revealed_value"))?,
		);
		let revealed_asset_id = u32::from_le_bytes(
			bytes[40..44]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid revealed_asset_id"))?,
		);
		let mut revealed_owner_hash = [0u8; 32];
		revealed_owner_hash.copy_from_slice(&bytes[44..76]);

		Ok(Self {
			commitment,
			revealed_value,
			revealed_asset_id,
			revealed_owner_hash,
		})
	}

	/// Validates consistency against the disclosure mask.
	///
	/// Rule: if the owner is NOT disclosed, `revealed_owner_hash` must be zero.
	pub fn validate(&self, mask: &DisclosureMask) -> Result<(), MemoError> {
		if !mask.disclose_owner && self.revealed_owner_hash != [0u8; 32] {
			return Err(MemoError::InvalidProof(
				"Owner hash must be zero when owner is not disclosed",
			));
		}
		Ok(())
	}

	/// Returns true when `revealed_value` is non-zero (helper for prover).
	pub fn disclose_value(&self) -> bool {
		self.revealed_value != 0
	}

	/// Returns true when `revealed_asset_id` is non-zero (helper for prover).
	pub fn disclose_asset_id(&self) -> bool {
		self.revealed_asset_id != 0
	}

	/// Returns true when `revealed_owner_hash` is non-zero (helper for prover).
	pub fn disclose_owner(&self) -> bool {
		self.revealed_owner_hash != [0u8; 32]
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_signals_new() {
		let s = DisclosurePublicSignals::new([1u8; 32], 1000, 5, [2u8; 32]);
		assert_eq!(s.commitment, [1u8; 32]);
		assert_eq!(s.revealed_value, 1000);
		assert_eq!(s.revealed_asset_id, 5);
		assert_eq!(s.revealed_owner_hash, [2u8; 32]);
	}

	#[test]
	fn test_signals_to_bytes_length() {
		let s = DisclosurePublicSignals::new([1u8; 32], 500, 2, [3u8; 32]);
		assert_eq!(s.to_bytes().len(), 76);
	}

	#[test]
	fn test_signals_roundtrip() {
		let original = DisclosurePublicSignals::new([10u8; 32], 1234, 56, [20u8; 32]);
		let recovered = DisclosurePublicSignals::from_bytes(&original.to_bytes()).unwrap();
		assert_eq!(recovered, original);
	}

	#[test]
	fn test_signals_from_bytes_invalid_length() {
		assert!(DisclosurePublicSignals::from_bytes(&[0u8; 50]).is_err());
	}

	#[test]
	fn test_signals_validate_ok() {
		let s = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]);
		assert!(s.validate(&DisclosureMask::only_value()).is_ok());
	}

	#[test]
	fn test_signals_validate_owner_hash_error() {
		let s = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [1u8; 32]);
		assert!(s.validate(&DisclosureMask::only_value()).is_err());
	}

	#[test]
	fn test_signals_helpers() {
		let s1 = DisclosurePublicSignals::new([0u8; 32], 1000, 5, [1u8; 32]);
		assert!(s1.disclose_value());
		assert!(s1.disclose_asset_id());
		assert!(s1.disclose_owner());

		let s2 = DisclosurePublicSignals::new([0u8; 32], 0, 0, [0u8; 32]);
		assert!(!s2.disclose_value());
		assert!(!s2.disclose_asset_id());
		assert!(!s2.disclose_owner());
	}

	#[test]
	fn test_signals_clone() {
		let s1 = DisclosurePublicSignals::new([5u8; 32], 999, 7, [10u8; 32]);
		let s2 = s1.clone();
		assert_eq!(s1, s2);
	}

	#[test]
	fn test_signals_to_bytes_content() {
		let commitment = [0xABu8; 32];
		let value: u64 = 1234;
		let asset_id: u32 = 56;
		let owner_hash = [0xCDu8; 32];

		let s = DisclosurePublicSignals::new(commitment, value, asset_id, owner_hash);
		let bytes = s.to_bytes();

		assert_eq!(&bytes[0..32], &commitment);
		assert_eq!(&bytes[32..40], &value.to_le_bytes());
		assert_eq!(&bytes[40..44], &asset_id.to_le_bytes());
		assert_eq!(&bytes[44..76], &owner_hash);
	}

	#[test]
	fn test_signals_validate_owner_disclosed_ok() {
		// owner IS disclosed — non-zero hash should be accepted
		use super::super::mask::DisclosureMask;
		let s = DisclosurePublicSignals::new([0u8; 32], 0, 0, [1u8; 32]);
		let mask = DisclosureMask::from_bitmap(0b0010); // owner only
		assert!(s.validate(&mask).is_ok());
	}
}
