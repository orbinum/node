//! The pallet's types: keys and their bookkeeping (this module), the interface
//! other pallets verify through ([`port`]) and what the runtime API returns
//! ([`runtime_api`]).
//!
//! The types storage and calls use stay in this module: their path is part of
//! the runtime metadata.

pub mod port;
pub mod runtime_api;

pub use port::{ShieldStatement, TransferStatement, UnshieldStatement, ZkVerifierPort};
pub use runtime_api::{CircuitVersionInfo, VkVersionHash};

use frame_support::pallet_prelude::*;
use parity_scale_codec::DecodeWithMemTracking;
use serde::{Deserialize, Serialize};

/// A serialized verifying key as stored: at most [`orbinum_zk_verifier::MAX_VK_BYTES`].
pub type VkBytes = BoundedVec<u8, ConstU32<{ orbinum_zk_verifier::MAX_VK_BYTES as u32 }>>;

/// A verifying key prepared once at registration, uncompressed: at most
/// [`orbinum_zk_verifier::MAX_PREPARED_VK_BYTES`].
pub type PreparedVkBytes =
	BoundedVec<u8, ConstU32<{ orbinum_zk_verifier::MAX_PREPARED_VK_BYTES as u32 }>>;

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
	/// Shield circuit ID
	pub const SHIELD: Self = Self(3);
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
	/// The serialized verification key data.
	pub key_data: VkBytes,
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
	/// Serialized verification key data.
	pub verification_key: VkBytes,
	/// Set this version as active after registration.
	/// If no active version exists for the circuit, it is activated regardless.
	pub set_active: bool,
}
