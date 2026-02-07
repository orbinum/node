//! AssetMetadata entity
//!
//! Represents metadata for assets that can be used in the shielded pool.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

/// Asset metadata for multi-asset shielded pool
///
/// Stores information about registered assets that can be used
/// in the shielded pool for private transactions.
///
/// # Domain Rules
/// - Asset ID must be unique
/// - Only verified assets can be used for transfers
/// - Only admin can verify assets
/// - Name must not be empty
/// - Symbol must be 1-16 characters
/// - Decimals typically 0-18
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug
)]
pub struct AssetMetadata<AccountId, BlockNumber> {
	/// Unique asset identifier
	pub id: u32,
	/// Human-readable asset name (e.g., "Tether USD")
	pub name: BoundedVec<u8, ConstU32<64>>,
	/// Asset symbol (e.g., "USDT")
	pub symbol: BoundedVec<u8, ConstU32<16>>,
	/// Number of decimal places
	pub decimals: u8,
	/// Whether this asset is verified for use (only admin can verify)
	pub is_verified: bool,
	/// Optional ERC20 contract address for bridged tokens
	pub contract_address: Option<[u8; 20]>,
	/// Block number when asset was registered
	pub created_at: BlockNumber,
	/// Account that registered this asset
	pub creator: AccountId,
}

impl<AccountId, BlockNumber> AssetMetadata<AccountId, BlockNumber> {
	/// Create new asset metadata
	pub fn new(
		id: u32,
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		created_at: BlockNumber,
		creator: AccountId,
	) -> Self {
		Self {
			id,
			name,
			symbol,
			decimals,
			is_verified: false,
			contract_address: None,
			created_at,
			creator,
		}
	}

	/// Verify the asset (only admin should call this)
	pub fn verify(&mut self) {
		self.is_verified = true;
	}

	/// Unverify the asset
	pub fn unverify(&mut self) {
		self.is_verified = false;
	}

	/// Check if asset is verified
	pub fn is_verified(&self) -> bool {
		self.is_verified
	}

	/// Set contract address
	pub fn set_contract_address(&mut self, address: [u8; 20]) {
		self.contract_address = Some(address);
	}
}
