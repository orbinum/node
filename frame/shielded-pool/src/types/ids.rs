//! Newtypes over the 32-byte field elements and the asset id.
//!
//! `Commitment` and `Nullifier` are both `[u8; 32]` underneath, and confusing
//! one for the other would be a silent correctness bug — the newtypes make that
//! a compile error instead.
//!
//! Both are stored as **raw bytes**, so byte equality is identity. Callers
//! feeding untrusted input must reject non-canonical encodings before they reach
//! storage; the ZK verifier does this today for anything backed by a proof.

use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::RuntimeDebug;

// Commitment

/// A commitment to a private note.
///
/// Computed as: `Poseidon(value, asset_id, owner_pubkey, blinding)`
#[derive(
	Clone,
	Copy,
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
pub struct Commitment(pub [u8; 32]);

impl Commitment {
	pub fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
	pub fn is_valid(&self) -> bool {
		self.0 != [0u8; 32]
	}
	pub fn is_zero(&self) -> bool {
		self.0 == [0u8; 32]
	}
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
	pub fn into_bytes(self) -> [u8; 32] {
		self.0
	}
}

impl From<[u8; 32]> for Commitment {
	fn from(b: [u8; 32]) -> Self {
		Self::new(b)
	}
}
impl From<H256> for Commitment {
	fn from(h: H256) -> Self {
		Self::new(h.0)
	}
}
impl AsRef<[u8]> for Commitment {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

// Nullifier

/// A nullifier identifying a spent note.
///
/// Computed as: `Poseidon(commitment, spending_key)`
#[derive(
	Clone,
	Copy,
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
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
	pub fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
	pub fn validate(&self) -> bool {
		self.0 != [0u8; 32]
	}
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
	pub fn into_bytes(self) -> [u8; 32] {
		self.0
	}
}

impl From<[u8; 32]> for Nullifier {
	fn from(b: [u8; 32]) -> Self {
		Self::new(b)
	}
}
impl From<H256> for Nullifier {
	fn from(h: H256) -> Self {
		Self::new(h.0)
	}
}
impl AsRef<[u8]> for Nullifier {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

// AssetId

/// Identifier for an asset in the shielded pool.
///
/// `0` = native (ORB), `1+` = registered external assets.
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug,
	Default,
	PartialOrd,
	Ord
)]
pub struct AssetId(pub u32);

impl AssetId {
	pub fn new(id: u32) -> Self {
		Self(id)
	}
	pub fn native() -> Self {
		Self(0)
	}
	pub fn is_native(&self) -> bool {
		self.0 == 0
	}
	pub fn inner(&self) -> u32 {
		self.0
	}
	pub fn is_valid(&self) -> bool {
		true
	}
}

impl From<u32> for AssetId {
	fn from(id: u32) -> Self {
		Self(id)
	}
}
impl From<AssetId> for u32 {
	fn from(a: AssetId) -> Self {
		a.0
	}
}

impl core::fmt::Display for AssetId {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		if self.is_native() {
			write!(f, "Native Asset (0)")
		} else {
			write!(f, "Asset {}", self.0)
		}
	}
}
