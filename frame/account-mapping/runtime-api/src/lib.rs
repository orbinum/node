#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use scale_info::TypeInfo;
use sp_core::H160;

/// A private chain link — only the commitment is stored on-chain (address never revealed).
#[derive(
	scale_codec::Encode,
	scale_codec::Decode,
	Clone,
	PartialEq,
	Eq,
	Debug,
	TypeInfo
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateLink {
	pub chain_id: u32,
	pub commitment: [u8; 32],
}

/// Compact alias info returned from the runtime API.
/// A link to an address on an external chain.
#[derive(
	scale_codec::Encode,
	scale_codec::Decode,
	Clone,
	PartialEq,
	Eq,
	Debug,
	TypeInfo
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainLink {
	pub chain_id: u32,
	pub address: Vec<u8>,
}

/// Metadata for an account's public profile.
#[derive(
	scale_codec::Encode,
	scale_codec::Decode,
	Clone,
	PartialEq,
	Eq,
	Debug,
	TypeInfo
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountMetadata {
	pub display_name: Option<Vec<u8>>,
	pub bio: Option<Vec<u8>>,
	pub avatar: Option<Vec<u8>>,
}

/// Compact alias info returned from the runtime API.
#[derive(
	scale_codec::Encode,
	scale_codec::Decode,
	Clone,
	PartialEq,
	Eq,
	Debug,
	TypeInfo
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct AliasInfo<AccountId> {
	pub owner: AccountId,
	pub evm_address: Option<H160>,
	pub chain_links_count: u32,
}

/// Full identity info including links and metadata.
#[derive(
	scale_codec::Encode,
	scale_codec::Decode,
	Clone,
	PartialEq,
	Eq,
	Debug,
	TypeInfo
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct FullIdentityInfo<AccountId> {
	pub owner: AccountId,
	pub evm_address: Option<H160>,
	pub chain_links: Vec<ChainLink>,
	pub metadata: Option<AccountMetadata>,
}

/// Compact listing info returned from the runtime API.
#[derive(
	scale_codec::Encode,
	scale_codec::Decode,
	Clone,
	PartialEq,
	Eq,
	Debug,
	TypeInfo
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ListingInfo<Balance> {
	/// Asking price in native tokens.
	pub price: Balance,
	/// True if a buyer whitelist is set (private OTC sale).
	pub private: bool,
	/// How many accounts are in the whitelist (0 if public).
	pub whitelist_count: u32,
}

pub use pallet_account_mapping::SignatureScheme;

sp_api::decl_runtime_apis! {
	pub trait AccountMappingRuntimeApi<AccountId, Balance>
	where
		AccountId: scale_codec::Codec,
		Balance: scale_codec::Codec,
	{
		fn get_mapped_account(address: H160) -> Option<AccountId>;
		fn get_mapped_address(account: AccountId) -> Option<H160>;
		fn get_fallback_address(account: AccountId) -> Option<H160>;

		/// Resolve an alias string to its identity info.
		/// Returns None if the alias is not registered.
		fn resolve_alias(alias: Vec<u8>) -> Option<AliasInfo<AccountId>>;

		/// Return the alias registered for a given AccountId, if any.
		fn get_alias_of(account: AccountId) -> Option<Vec<u8>>;

		// ── Marketplace queries ────────────────────────────────────────────

		/// Get sale listing info for a given alias.
		/// Returns None if the alias is not listed for sale.
		fn get_listing_info(alias: Vec<u8>) -> Option<ListingInfo<Balance>>;

		/// Return the alias listed for sale by the given account, if any.
		/// Returns (alias_bytes, listing_info) or None.
		fn get_account_listing(account: AccountId) -> Option<(Vec<u8>, ListingInfo<Balance>)>;

		/// Check if a given buyer can purchase the specified alias.
		/// Returns false if: alias not for sale, buyer already has an alias,
		/// or buyer is not in the whitelist.
		fn can_buy(alias: Vec<u8>, buyer: AccountId) -> bool;

		/// Get full identity info for an alias.
		fn get_full_identity(alias: Vec<u8>) -> Option<FullIdentityInfo<AccountId>>;

		/// Get metadata for a specific account.
		fn get_account_metadata(account: AccountId) -> Option<AccountMetadata>;

		/// Get the owner of a verified multichain link.
		fn get_link_owner(chain_id: u32, address: Vec<u8>) -> Option<AccountId>;

		/// Get all supported chains and their signature schemes.
		fn get_supported_chains() -> Vec<(u32, SignatureScheme)>;

		// ── Private link queries ───────────────────────────────────────────

		/// Return the list of private chain link commitments for an alias.
		/// The real addresses are never stored on-chain.
		/// Returns None if the alias does not exist.
		fn get_private_links(alias: Vec<u8>) -> Option<Vec<PrivateLink>>;

		/// Check whether a specific commitment is registered as a private link
		/// for the given alias.
		fn has_private_link(alias: Vec<u8>, commitment: [u8; 32]) -> bool;
	}
}
