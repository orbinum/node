//! # Note Structure
//!
//! A note represents a private value in the shielded pool.
//!
//! ## Structure
//!
//! ```text
//! Note {
//!     value: u64          // Token amount (hidden)
//!     asset_id: u64       // Token type (hidden)
//!     owner_pubkey: Fr    // Owner's public key (hidden)
//!     blinding: Fr        // Random factor (prevents correlation)
//! }
//! ```
//!
//! ## Commitment
//!
//! A note's commitment is stored in the Merkle tree:
//! ```text
//! commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
//! ```
//!
//! ## Nullifier
//!
//! When spending a note, a nullifier is published to prevent double-spending:
//! ```text
//! nullifier = Poseidon(commitment, spending_key)
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_primitives::models::note::Note;
//!
//! // Create a note
//! let note = Note::new(100, 0, owner_pubkey, blinding);
//!
//! // Get commitment (for Merkle tree)
//! let commitment = note.commitment();
//!
//! // Get nullifier (when spending)
//! let nullifier = note.nullifier(&spending_key);
//! ```

use crate::core::types::{Blinding, Bn254Fr, Commitment, Nullifier, OwnerPubkey, SpendingKey};
use crate::crypto::commitment::{compute_nullifier, create_commitment};

// ============================================================================
// Note Structure
// ============================================================================

/// Represents a private note in the shielded pool
#[derive(Clone, Debug, PartialEq)]
pub struct Note {
	/// Token amount
	pub value: Bn254Fr,
	/// Token type identifier
	pub asset_id: Bn254Fr,
	/// Public key of the owner
	pub owner_pubkey: OwnerPubkey,
	/// Random blinding factor
	pub blinding: Blinding,
}

impl Note {
	/// Creates a new note
	pub fn new(value: u64, asset_id: u64, owner_pubkey: OwnerPubkey, blinding: Blinding) -> Self {
		Self {
			value: Bn254Fr::from(value),
			asset_id: Bn254Fr::from(asset_id),
			owner_pubkey,
			blinding,
		}
	}

	/// Creates a new note from field elements
	pub fn from_fields(
		value: Bn254Fr,
		asset_id: Bn254Fr,
		owner_pubkey: OwnerPubkey,
		blinding: Blinding,
	) -> Self {
		Self {
			value,
			asset_id,
			owner_pubkey,
			blinding,
		}
	}

	/// Computes the commitment for this note
	pub fn commitment(&self) -> Commitment {
		create_commitment(self.value, self.asset_id, self.owner_pubkey, self.blinding)
	}

	/// Computes the nullifier for this note
	pub fn nullifier(&self, spending_key: &SpendingKey) -> Nullifier {
		let commitment = self.commitment();
		compute_nullifier(&commitment, spending_key)
	}

	/// Creates a zero note (for padding)
	pub fn zero() -> Self {
		Self {
			value: Bn254Fr::from(0u64),
			asset_id: Bn254Fr::from(0u64),
			owner_pubkey: Bn254Fr::from(0u64),
			blinding: Bn254Fr::from(0u64),
		}
	}

	/// Returns the value as u64 (may return None if value doesn't fit)
	pub fn value_u64(&self) -> Option<u64> {
		use ark_ff::{BigInteger, PrimeField};
		let bytes = self.value.into_bigint().to_bytes_le();
		if bytes.len() >= 8 {
			Some(u64::from_le_bytes([
				bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
			]))
		} else {
			None
		}
	}

	/// Returns the asset_id as u64 (may return None if asset_id doesn't fit)
	pub fn asset_id_u64(&self) -> Option<u64> {
		use ark_ff::{BigInteger, PrimeField};
		let bytes = self.asset_id.into_bigint().to_bytes_le();
		if bytes.len() >= 8 {
			Some(u64::from_le_bytes([
				bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
			]))
		} else {
			None
		}
	}
}
