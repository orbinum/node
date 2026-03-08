use frame_support::pallet_prelude::*;

/// Maximum number of external links (public or private) per identity.
pub const MAX_CHAIN_LINKS: u32 = 16;

/// Maximum length in bytes of an external address (covers BTC bech32, etc.).
pub const MAX_EXTERNAL_ADDR_LEN: u32 = 128;

/// Maximum number of buyers in a private sale whitelist.
pub const MAX_WHITELIST_SIZE: u32 = 20;

/// Maximum length for metadata strings (bio, avatar CID, etc.).
pub const MAX_METADATA_LEN: u32 = 128;

/// Opaque chain identifier used as storage key for cross-chain links.
///
/// The `u32` namespace is split into two ranges using the high bit (bit 31):
///
/// | Bit 31 | Range | Standard | Examples |
/// |--------|-------|----------|---------|
/// | `0` | `0x0000_0000 – 0x7FFF_FFFF` | EIP-155 (EVM chain IDs) | Ethereum = 1, Polygon = 137 |
/// | `1` | `0x8000_0000 – 0xFFFF_FFFF` | SLIP-0044 (HD wallet coin types) | Bitcoin = `0x8000_0000`, Solana = `0x8000_01F5` |
///
/// Use `SLIP0044_NAMESPACE | <coin_type>` to build SLIP-0044 identifiers.
/// Canonical constants for well-known chains are defined in `protocol-core`.
/// Governance MUST follow this convention when registering chains via `add_supported_chain`.
pub type ChainId = u32;

/// Bitmask to set bit 31, placing a coin type in the SLIP-0044 namespace.
/// Example: `SLIP0044_NAMESPACE | 0` = Bitcoin, `SLIP0044_NAMESPACE | 501` = Solana.
pub const SLIP0044_NAMESPACE: u32 = 0x8000_0000;

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
/// Signature verification scheme used to prove ownership of a cross-chain wallet.
///
/// # Design invariant
///
/// Every variant MUST represent an **external, non-Substrate-native** signing scheme.
/// Substrate-native schemes (Sr25519, Ed25519-Substrate, etc.) MUST NOT be added here
/// because an `AccountId32` is already self-proving in the Substrate key model — no
/// cross-chain proof of ownership is required or meaningful. `add_supported_chain`
/// enforces this invariant at the governance call level via `is_for_external_chain()`.
pub enum SignatureScheme {
	/// Ethereum-style EIP-191 (ECDSA over Keccak256).
	Eip191,
	/// Solana-style raw Ed25519 (not the Substrate Ed25519 wrapper).
	Ed25519,
}

impl SignatureScheme {
	/// Returns `true` if this scheme belongs to a non-Substrate-native ecosystem.
	///
	/// All current variants are external. Any future variant for a Substrate-native
	/// scheme MUST return `false` here so that `add_supported_chain` rejects it.
	pub fn is_for_external_chain(&self) -> bool {
		match self {
			SignatureScheme::Eip191 => true,
			SignatureScheme::Ed25519 => true,
		}
	}
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
