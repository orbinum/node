//! Value proof types for Orbinum ZK note verification.
//!
//! These types model the public signals of the `value_proof` circuit (CircuitId 6):
//! a Groth16 proof that proves a note commitment encodes a specific value and asset,
//! without revealing the blinding factor or the raw owner public key.
//!
//! # Public signals layout (76 bytes)
//!
//! ```text
//! commitment(32) | value(8) | asset_id(4) | owner_hash(32)
//! ```
//!
//! Proves: `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
//!
//! # Types
//!
//! - [`ValueProofPublicSignals`] — on-chain verified public signals (76 bytes)
//! - [`ValueProof`] — proof + signals bundled for submission

use alloc::vec::Vec;

use crate::memo::MemoError;

#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use scale_info::TypeInfo;

// ─── ValueProofPublicSignals ─────────────────────────────────────────────────

/// Public signals produced by the `value_proof` circuit (CircuitId 6) and verified on-chain.
///
/// Fixed serialized size: **76 bytes**
/// Layout: `commitment(32) | value(8) | asset_id(4) | owner_hash(32)`
///
/// All four fields are always present — the value_proof circuit unconditionally
/// reveals commitment, value, asset_id and the owner public key hash.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct ValueProofPublicSignals {
	/// Commitment binding the proof to a specific on-chain note.
	pub commitment: [u8; 32],
	/// Token amount encoded in the commitment (LE u64).
	pub value: u64,
	/// Asset identifier encoded in the commitment.
	pub asset_id: u32,
	/// Poseidon hash of the owner public key (not the raw key).
	pub owner_hash: [u8; 32],
}

impl ValueProofPublicSignals {
	/// Creates new public signals.
	pub fn new(commitment: [u8; 32], value: u64, asset_id: u32, owner_hash: [u8; 32]) -> Self {
		Self { commitment, value, asset_id, owner_hash }
	}

	/// Serializes to exactly 76 bytes.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(76);
		bytes.extend_from_slice(&self.commitment);
		bytes.extend_from_slice(&self.value.to_le_bytes());
		bytes.extend_from_slice(&self.asset_id.to_le_bytes());
		bytes.extend_from_slice(&self.owner_hash);
		bytes
	}

	/// Deserializes from exactly 76 bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() != 76 {
			return Err(MemoError::InvalidProof(
				"Invalid public signals length (expected 76 bytes)",
			));
		}
		let mut commitment = [0u8; 32];
		commitment.copy_from_slice(&bytes[0..32]);
		let value = u64::from_le_bytes(
			bytes[32..40]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid value bytes"))?,
		);
		let asset_id = u32::from_le_bytes(
			bytes[40..44]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid asset_id bytes"))?,
		);
		let mut owner_hash = [0u8; 32];
		owner_hash.copy_from_slice(&bytes[44..76]);
		Ok(Self { commitment, value, asset_id, owner_hash })
	}
}

// ─── ValueProof ──────────────────────────────────────────────────────────────

/// Value proof ready for on-chain verification (CircuitId 6).
///
/// Serialized layout: `proof_len(2) || proof(n) || public_signals(76)`
///
/// The Groth16 proof for BN254 is always 128 bytes. `validate()` enforces this.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct ValueProof {
	/// Raw Groth16 proof bytes (BN254: 128 bytes).
	pub proof: Vec<u8>,
	/// Public signals verified on-chain.
	pub public_signals: ValueProofPublicSignals,
}

impl ValueProof {
	/// Creates a new value proof.
	pub fn new(proof: Vec<u8>, public_signals: ValueProofPublicSignals) -> Self {
		Self { proof, public_signals }
	}

	/// Serializes: `proof_len(2) || proof(n) || signals(76)`
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&(self.proof.len() as u16).to_le_bytes());
		bytes.extend_from_slice(&self.proof);
		bytes.extend_from_slice(&self.public_signals.to_bytes());
		bytes
	}

	/// Deserializes from bytes produced by [`to_bytes`].
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() < 2 {
			return Err(MemoError::InvalidProof("Value proof too short"));
		}
		let proof_len = u16::from_le_bytes(
			bytes[0..2]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid proof length field"))?,
		) as usize;
		if bytes.len() < 2 + proof_len + 76 {
			return Err(MemoError::InvalidProof("Value proof bytes truncated"));
		}
		let proof = bytes[2..2 + proof_len].to_vec();
		let public_signals =
			ValueProofPublicSignals::from_bytes(&bytes[2 + proof_len..2 + proof_len + 76])?;
		Ok(Self { proof, public_signals })
	}

	/// Validates before on-chain submission.
	///
	/// A valid BN254 Groth16 proof is exactly 128 bytes.
	pub fn validate(&self) -> Result<(), MemoError> {
		if self.proof.is_empty() {
			return Err(MemoError::InvalidProof("Proof is empty"));
		}
		if self.proof.len() != 128 {
			return Err(MemoError::InvalidProof(
				"Groth16 BN254 proof must be exactly 128 bytes",
			));
		}
		Ok(())
	}
}
