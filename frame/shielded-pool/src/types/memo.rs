//! Encrypted memo attached to a commitment.
//!
//! Fixed at exactly `MAX_ENCRYPTED_MEMO_SIZE` bytes with a fixed field layout,
//! which is what lets the accessors slice it by offset. Those accessors are
//! defensive anyway — they return an empty slice rather than panicking if the
//! invariant is ever violated, since a panic here would be reachable from a
//! dispatchable.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

// EncryptedMemo (concrete, FRAME-compatible — used in storage & extrinsics)

/// Max encrypted memo size: `nonce(12) + ciphertext(120) + MAC(16) + ephPk(32) = 180`.
pub const MAX_ENCRYPTED_MEMO_SIZE: u32 = 180;

/// Encrypted memo attached to a commitment (ChaCha20-Poly1305).
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
	pub fn new(data: Vec<u8>) -> Result<Self, &'static str> {
		BoundedVec::try_from(data)
			.map(Self)
			.map_err(|_| "Memo size exceeds maximum")
	}
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}
	pub fn is_valid_size(&self) -> bool {
		!self.0.is_empty()
	}
	pub fn len(&self) -> usize {
		self.0.len()
	}
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		if bytes.len() != MAX_ENCRYPTED_MEMO_SIZE as usize {
			return Err("Invalid memo size");
		}
		Self::new(bytes.to_vec())
	}
	pub fn nonce(&self) -> &[u8] {
		// Invariant: EncryptedMemo is always exactly MAX_ENCRYPTED_MEMO_SIZE bytes after
		// construction. from_bytes() enforces this; the else branch is unreachable in practice.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 12 {
			&self.0[..12]
		} else {
			&[]
		}
	}
	pub fn ciphertext(&self) -> &[u8] {
		// Invariant: see nonce(). ciphertext occupies bytes 12..132.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 132 {
			&self.0[12..132]
		} else {
			&[]
		}
	}
	pub fn tag(&self) -> &[u8] {
		// Layout: nonce(0..12) | ciphertext(12..132) | tag/MAC(132..148) | ephPk(148..180)
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 148 {
			&self.0[132..148]
		} else {
			&[]
		}
	}
	pub fn eph_pk(&self) -> &[u8] {
		// Ephemeral BabyJubJub public key (packed, LE) occupies bytes 148..180.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 180 {
			&self.0[148..180]
		} else {
			&[]
		}
	}
}
