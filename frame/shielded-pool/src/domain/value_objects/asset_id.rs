//! AssetId value object
//!
//! Represents which asset a note or operation refers to.
//! 0 = native asset (ORB), >0 = registered external assets

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

/// Identifier for an asset in the shielded pool
///
/// - 0: Native asset (ORB)
/// - 1+: External registered assets (e.g., USDT, USDC)
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
	/// Create a new AssetId
	pub fn new(id: u32) -> Self {
		Self(id)
	}

	/// Get the native asset ID (0)
	pub fn native() -> Self {
		Self(0)
	}

	/// Check if this is the native asset
	pub fn is_native(&self) -> bool {
		self.0 == 0
	}

	/// Get the raw u32 value
	pub fn inner(&self) -> u32 {
		self.0
	}

	/// Check if this asset ID is valid (not reserved)
	pub fn is_valid(&self) -> bool {
		// Could add validation logic here
		// For example, checking against reserved IDs
		true
	}
}

impl From<u32> for AssetId {
	fn from(id: u32) -> Self {
		Self(id)
	}
}

impl From<AssetId> for u32 {
	fn from(asset_id: AssetId) -> Self {
		asset_id.0
	}
}

impl core::fmt::Display for AssetId {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		if self.is_native() {
			write!(f, "Native Asset ({})", self.0)
		} else {
			write!(f, "Asset {}", self.0)
		}
	}
}
