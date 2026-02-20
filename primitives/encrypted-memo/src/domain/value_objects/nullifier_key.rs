//! Nullifier Key value object.
//!
//! Used to derive nullifiers for spent notes, preventing double-spending.
//! Derived from spending key via `SHA256(spending_key || NULLIFIER_KEY_DOMAIN)`.

#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use scale_info::TypeInfo;

/// Nullifier derivation key.
///
/// Used to compute `nullifier = Poseidon(commitment, nullifier_key)`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct NullifierKey(pub [u8; 32]);

impl NullifierKey {
	/// Creates a nullifier key from raw bytes.
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the raw key bytes.
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::format;

	const BYTES: [u8; 32] = [17u8; 32];

	#[test]
	fn test_from_bytes_stores_inner() {
		assert_eq!(NullifierKey::from_bytes(BYTES).0, BYTES);
	}

	#[test]
	fn test_as_bytes_returns_reference() {
		assert_eq!(NullifierKey::from_bytes(BYTES).as_bytes(), &BYTES);
	}

	#[test]
	fn test_as_ref() {
		let k = NullifierKey::from_bytes(BYTES);
		let r: &[u8; 32] = k.as_ref();
		assert_eq!(r, &BYTES);
	}

	#[test]
	fn test_from_trait() {
		let k: NullifierKey = BYTES.into();
		assert_eq!(k.0, BYTES);
	}

	#[test]
	fn test_clone_eq() {
		let k1 = NullifierKey::from_bytes(BYTES);
		assert_eq!(k1.clone(), k1);
	}

	#[test]
	fn test_ne_different_bytes() {
		assert_ne!(
			NullifierKey::from_bytes([1u8; 32]),
			NullifierKey::from_bytes([2u8; 32])
		);
	}

	#[test]
	fn test_debug_contains_type_name() {
		let s = format!("{:?}", NullifierKey::from_bytes([0u8; 32]));
		assert!(s.contains("NullifierKey"));
	}

	#[test]
	fn test_all_zeros() {
		assert_eq!(NullifierKey::from_bytes([0u8; 32]).as_bytes(), &[0u8; 32]);
	}

	#[test]
	fn test_all_ones() {
		assert_eq!(
			NullifierKey::from_bytes([0xFFu8; 32]).as_bytes(),
			&[0xFFu8; 32]
		);
	}
}
