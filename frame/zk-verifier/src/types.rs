//! Types for the ZK Verifier pallet.

use frame_support::pallet_prelude::*;
use parity_scale_codec::DecodeWithMemTracking;
use serde::{Deserialize, Serialize};

extern crate alloc;

/// Circuit identifier type (pallet-specific wrapper)
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
	Debug,
	Default,
	Serialize,
	Deserialize
)]
pub struct CircuitId(pub u32);

impl CircuitId {
	/// Transfer circuit ID
	pub const TRANSFER: Self = Self(1);
	/// Unshield circuit ID
	pub const UNSHIELD: Self = Self(2);
	/// Private link dispatch circuit ID
	pub const PRIVATE_LINK: Self = Self(5);
	/// Value proof circuit ID — proves commitment encodes (value, asset_id) before fee insertion
	pub const VALUE_PROOF: Self = Self(6);
}

/// Supported proof systems
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Debug,
	Default,
	Serialize,
	Deserialize
)]
pub enum ProofSystem {
	/// Groth16 - Most efficient for on-chain verification
	#[default]
	Groth16,
	/// PLONK - Universal setup, larger proofs
	Plonk,
	/// Halo2 - No trusted setup
	Halo2,
}

/// Information about a stored verification key
#[derive(Clone, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
pub struct VerificationKeyInfo<BlockNumber> {
	/// The serialized verification key data (max 8KB)
	pub key_data: BoundedVec<u8, ConstU32<8192>>,
	/// The proof system this key is for
	pub system: ProofSystem,
	/// Block number when the key was registered
	pub registered_at: BlockNumber,
}

impl<BlockNumber: Default> Default for VerificationKeyInfo<BlockNumber> {
	fn default() -> Self {
		Self {
			key_data: Default::default(),
			system: Default::default(),
			registered_at: Default::default(),
		}
	}
}

/// Statistics for proof verification
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	Debug,
	Default
)]
pub struct VerificationStatistics {
	/// Total verification attempts
	pub total_verifications: u64,
	/// Successful verifications
	pub successful_verifications: u64,
	/// Failed verifications
	pub failed_verifications: u64,
}

/// A single entry for batch verification key registration.
///
/// Used by `batch_register_verification_keys` to atomically register
/// and optionally activate multiple circuits in one extrinsic.
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Debug
)]
pub struct VkEntry {
	/// Circuit to register the key for.
	pub circuit_id: CircuitId,
	/// Version number for this key.
	pub version: u32,
	/// Serialized verification key data (max 8 KB).
	pub verification_key: BoundedVec<u8, ConstU32<8192>>,
	/// Set this version as active after registration.
	/// If no active version exists for the circuit, it is activated regardless.
	pub set_active: bool,
}

// ─── Runtime API response types ───────────────────────────────────────────────

/// (version, VK hash) pair used in [`CircuitVersionInfo`].
#[derive(
	Clone,
	PartialEq,
	Eq,
	parity_scale_codec::Encode,
	parity_scale_codec::Decode,
	scale_info::TypeInfo,
	Debug
)]
pub struct VkVersionHash {
	pub version: u32,
	pub vk_hash: [u8; 32],
}

/// Versioning summary for one circuit, returned by runtime API queries.
#[derive(
	Clone,
	PartialEq,
	Eq,
	parity_scale_codec::Encode,
	parity_scale_codec::Decode,
	scale_info::TypeInfo,
	Debug
)]
pub struct CircuitVersionInfo {
	pub circuit_id: u32,
	pub active_version: u32,
	pub supported_versions: alloc::vec::Vec<u32>,
	pub vk_hashes: alloc::vec::Vec<VkVersionHash>,
}
