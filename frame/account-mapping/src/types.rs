use frame_support::pallet_prelude::*;

/// Maximum number of external links (public or private) per identity.
pub const MAX_CHAIN_LINKS: u32 = 16;

/// Maximum length in bytes of an external address (covers BTC bech32, etc.).
pub const MAX_EXTERNAL_ADDR_LEN: u32 = 128;

/// Maximum number of buyers in a private sale whitelist.
pub const MAX_WHITELIST_SIZE: u32 = 20;

/// Maximum length for metadata strings (bio, avatar CID, etc.).
pub const MAX_METADATA_LEN: u32 = 128;

pub type ChainId = u32;
pub type ExternalAddr = BoundedVec<u8, ConstU32<MAX_EXTERNAL_ADDR_LEN>>;

#[derive(
	Encode,
	Decode,
	Clone,
	PartialEq,
	Eq,
	RuntimeDebug,
	TypeInfo,
	MaxEncodedLen,
	scale_codec::DecodeWithMemTracking
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum SignatureScheme {
	/// Ethereum-style EIP-191 (ECDSA over Keccak256).
	Eip191,
	/// Solana-style Ed25519 (raw signature of the message).
	Ed25519,
}

#[derive(
	Encode,
	Decode,
	Clone,
	PartialEq,
	Eq,
	RuntimeDebug,
	TypeInfo,
	MaxEncodedLen,
	Default
)]
pub struct AccountMetadata {
	pub display_name: Option<BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>>,
	pub bio: Option<BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>>,
	pub avatar: Option<BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>>,
}

#[derive(
	Encode,
	Decode,
	Clone,
	PartialEq,
	Eq,
	RuntimeDebug,
	TypeInfo,
	MaxEncodedLen
)]
pub struct ChainLink {
	pub chain_id: ChainId,
	pub address: ExternalAddr,
}

#[derive(
	Encode,
	Decode,
	Clone,
	PartialEq,
	Eq,
	RuntimeDebug,
	TypeInfo,
	MaxEncodedLen
)]
pub struct PrivateChainLink {
	pub chain_id: ChainId,
	pub commitment: [u8; 32],
}
