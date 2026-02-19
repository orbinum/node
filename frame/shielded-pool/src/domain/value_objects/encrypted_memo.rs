//! EncryptedMemo value object
//!
//! Represents encrypted metadata attached to a commitment for auditing purposes.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

/// Maximum size for an encrypted memo (in bytes)
///
/// Must match the output of ChaCha20Poly1305 encryption:
/// `nonce(12) + note_data(76) + MAC(16) = 104`
pub const MAX_MEMO_SIZE: u32 = 104;

/// Standard encrypted memo with default max size
pub type StandardEncryptedMemo = EncryptedMemo<ConstU32<MAX_MEMO_SIZE>>;

/// An encrypted memo containing note metadata for selective disclosure
///
/// The memo can contain:
/// - Note value
/// - Asset ID
/// - Sender information
/// - Purpose/description
/// - Timestamp
///
/// Encrypted with the auditor's viewing key, allowing selective disclosure
/// to authorized parties without revealing information to the public.
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
pub struct EncryptedMemo<MaxSize: Get<u32>>(pub BoundedVec<u8, MaxSize>);

impl<MaxSize: Get<u32>> EncryptedMemo<MaxSize> {
	/// Create a new encrypted memo from bytes
	pub fn new(data: Vec<u8>) -> Result<Self, &'static str> {
		BoundedVec::try_from(data)
			.map(Self)
			.map_err(|_| "Memo size exceeds maximum")
	}

	/// Create from a bounded vec
	pub fn from_bounded(data: BoundedVec<u8, MaxSize>) -> Self {
		Self(data)
	}

	/// Get the inner bytes
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Get the size of the memo
	pub fn size(&self) -> u32 {
		self.0.len() as u32
	}

	/// Check if the memo is empty
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Validate the memo size
	pub fn is_valid_size(&self) -> bool {
		let size = self.size();
		size > 0 && size <= MaxSize::get()
	}
}

impl<MaxSize: Get<u32> + TypeInfo> TryFrom<Vec<u8>> for EncryptedMemo<MaxSize> {
	type Error = &'static str;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		Self::new(value)
	}
}
