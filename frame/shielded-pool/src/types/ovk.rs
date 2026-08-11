//! The outgoing-viewing-key blob published with each private transfer.
//!
//! A memo is sealed toward the RECIPIENT, so its sender cannot reopen it — a
//! sender who loses their vault loses the record of what they sent. This blob
//! is the fix: it wraps that memo's shared secret under the sender's outgoing
//! viewing key, so the sender can reach the same plaintext the recipient does.
//!
//! The chain treats it as opaque. It cannot be validated: the contents are
//! ciphertext, and nothing on chain holds the key to check them against. Only
//! the length is guaranteed, and the type is what guarantees it.

use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

/// Blob size: `nonce_suffix(8) + ciphertext(32) + MAC(16) = 56`.
pub const OVK_BLOB_SIZE: usize = 56;

/// Outgoing-viewing-key blob: `nonce_suffix(8) || ciphertext(32) || MAC(16)`.
///
/// ALWAYS present and ALWAYS 56 bytes. The fixed-size array is what enforces
/// that — a `BoundedVec` would leave the length to programmer discipline, and
/// the SCALE codec rejects anything else before the extrinsic is even decoded.
///
/// A sender who opts out of recoverability sends 56 RANDOM bytes, not zeros.
/// Zeros would be greppable: opting out would mark the transaction forever, and
/// every user who did so would form a trivially identifiable set. Random bytes
/// are indistinguishable from a real blob, so opting out reveals nothing.
///
/// There is deliberately no `Default`. It would produce exactly the 56 zeros
/// the design forbids, from a call that takes no arguments and reads as
/// harmless — build one with [`OvkBlob::from_bytes`] instead.
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug
)]
pub struct OvkBlob(pub [u8; OVK_BLOB_SIZE]);

impl OvkBlob {
	/// Builds a blob from raw bytes, rejecting any length other than 56.
	///
	/// This is the EVM route's length check: calldata carries a dynamic `bytes`,
	/// so unlike the SCALE route nothing upstream has pinned the size yet.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		let arr: [u8; OVK_BLOB_SIZE] = bytes.try_into().map_err(|_| "Invalid ovk blob size")?;
		Ok(Self(arr))
	}

	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}
