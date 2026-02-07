//! FRAME-specific type adaptations
//!
//! This module contains types that need FRAME-specific traits (like ConstU32)
//! to work properly with Substrate macros and storage.
//!
//! These are technical adaptations (infrastructure layer) rather than domain types.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

/// Maximum size for an encrypted memo (in bytes)
pub const MAX_ENCRYPTED_MEMO_SIZE: u32 = 256;

/// Encrypted memo for commitments (FRAME-specific type with ConstU32)
///
/// This type uses `ConstU32` from `frame_support` to ensure compatibility
/// with FRAME macros and storage. This is a technical adapter in the infrastructure
/// layer - the generic domain version exists in `domain::value_objects::EncryptedMemo`.
///
/// This is the type that should be used in pallet storage and extrinsics.
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug,
	Default
)]
pub struct EncryptedMemo(pub BoundedVec<u8, ConstU32<MAX_ENCRYPTED_MEMO_SIZE>>);

impl EncryptedMemo {
	/// Create a new encrypted memo from bytes
	pub fn new(data: Vec<u8>) -> Result<Self, &'static str> {
		BoundedVec::try_from(data)
			.map(Self)
			.map_err(|_| "Memo size exceeds maximum")
	}

	/// Get as bytes
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Check if valid size
	pub fn is_valid_size(&self) -> bool {
		!self.0.is_empty()
	}

	/// Get length
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Check if empty
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Create from bytes slice (for compatibility with tests)
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		if bytes.len() != MAX_ENCRYPTED_MEMO_SIZE as usize {
			return Err("Invalid memo size");
		}
		Self::new(bytes.to_vec())
	}

	/// Get nonce (first 24 bytes)
	pub fn nonce(&self) -> &[u8] {
		if self.0.len() >= 24 {
			&self.0[..24]
		} else {
			&[]
		}
	}

	/// Get ciphertext (bytes 24-87, 64 bytes)
	pub fn ciphertext(&self) -> &[u8] {
		if self.0.len() >= 88 {
			&self.0[24..88]
		} else {
			&[]
		}
	}

	/// Get authentication tag (last 16 bytes)
	pub fn tag(&self) -> &[u8] {
		if self.0.len() >= 104 {
			&self.0[88..104]
		} else {
			&[]
		}
	}
}
