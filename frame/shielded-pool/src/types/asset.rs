//! Registered asset metadata.
//!
//! An asset must be both registered and verified before it can be shielded or
//! unshielded; `is_verified` doubles as a governance kill-switch for an asset
//! found to be compromised.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

// AssetMetadata

/// Asset metadata for multi-asset shielded pool.
#[derive(Clone, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
pub struct AssetMetadata<AccountId, BlockNumber> {
	pub id: u32,
	pub name: BoundedVec<u8, ConstU32<64>>,
	pub symbol: BoundedVec<u8, ConstU32<16>>,
	pub decimals: u8,
	pub is_verified: bool,
	pub contract_address: Option<[u8; 20]>,
	pub created_at: BlockNumber,
	pub creator: AccountId,
}

impl<AccountId, BlockNumber> AssetMetadata<AccountId, BlockNumber> {
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
	pub fn verify(&mut self) {
		self.is_verified = true;
	}
	pub fn unverify(&mut self) {
		self.is_verified = false;
	}
	pub fn is_verified(&self) -> bool {
		self.is_verified
	}
	pub fn set_contract_address(&mut self, address: [u8; 20]) {
		self.contract_address = Some(address);
	}
}
