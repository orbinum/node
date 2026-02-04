//! Types for the ZK Verifier pallet
//!
//! This module contains ONLY runtime types for FRAME storage and extrinsics.
//! Domain types are in domain/, primitive adapters are in infrastructure/adapters.
//!
//! Following Clean Architecture:
//! - These types are for the Presentation/Infrastructure boundary (FRAME runtime)
//! - They are converted to domain types before use case execution via extrinsics.rs
//! - They should NOT be used directly in domain logic
//! - Primitives (orbinum-zk-verifier, orbinum-zk-core) are accessed ONLY via infrastructure/adapters

use frame_support::pallet_prelude::*;
use parity_scale_codec::DecodeWithMemTracking;
use serde::{Deserialize, Serialize};

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
	/// Disclosure circuit ID
	pub const DISCLOSURE: Self = Self(4);
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

/// Metadata about a circuit
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
pub struct CircuitMetadata {
	/// Number of public inputs expected
	pub num_public_inputs: u32,
	/// Number of constraints in the circuit
	pub num_constraints: u64,
	/// Circuit version
	pub version: u32,
	/// Whether the circuit is active
	pub is_active: bool,
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
