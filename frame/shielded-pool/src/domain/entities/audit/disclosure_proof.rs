//! DisclosureProof entity
//!
//! Represents a zero-knowledge proof of compliance with disclosure conditions.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

use crate::domain::Commitment;

/// Disclosure proof (ZK proof of compliance)
///
/// # Domain Rules
/// - Commitment must exist in the Merkle tree
/// - ZK proof must be valid
/// - Disclosed data is encrypted for auditor only
/// - Timestamp prevents replay attacks
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	TypeInfo,
	RuntimeDebug,
	MaxEncodedLen
)]
pub struct DisclosureProof {
	/// The commitment being disclosed
	pub commitment: Commitment,
	/// ZK proof proving the disclosure conditions are met
	pub zk_proof: BoundedVec<u8, ConstU32<2048>>,
	/// Disclosed attributes (encrypted for auditor only)
	pub disclosed_data: BoundedVec<u8, ConstU32<512>>,
	/// Proof timestamp
	pub timestamp: u64,
}

impl DisclosureProof {
	/// Create new disclosure proof
	pub fn new(
		commitment: Commitment,
		zk_proof: BoundedVec<u8, ConstU32<2048>>,
		disclosed_data: BoundedVec<u8, ConstU32<512>>,
		timestamp: u64,
	) -> Self {
		Self {
			commitment,
			zk_proof,
			disclosed_data,
			timestamp,
		}
	}

	/// Get commitment
	pub fn commitment(&self) -> &Commitment {
		&self.commitment
	}

	/// Get proof size
	pub fn proof_size(&self) -> usize {
		self.zk_proof.len()
	}

	/// Get disclosed data size
	pub fn data_size(&self) -> usize {
		self.disclosed_data.len()
	}

	/// Get timestamp
	pub fn timestamp(&self) -> u64 {
		self.timestamp
	}
}
