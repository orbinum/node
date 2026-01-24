//! # Note Commitment and Nullifier Gadgets
//!
//! Implements the core privacy primitives for the shielded pool:
//!
//! - **Note Commitment**: `H(value, asset_id, owner_pubkey, blinding)`
//!   - Commits to a note's content without revealing it
//!   - The blinding factor ensures hiding property
//!
//! - **Nullifier**: `H(commitment, spending_key)`
//!   - Uniquely identifies a note being spent
//!   - Prevents double-spending without revealing which note
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_circuits::circuits::note::*;
//!
//! // Create a note commitment
//! let commitment = note_commitment_native(1000, 1, owner_pubkey, blinding);
//!
//! // Compute nullifier when spending
//! let nullifier = nullifier_native(commitment, spending_key);
//! ```
//!
//! ## Compatibility
//!
//! These implementations match the circomlib-based Circom circuits
//! using Poseidon hash with circomlib parameters.

use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// Import from fp-zk-primitives
use fp_zk_primitives::crypto::hash::{
	poseidon_hash_2 as poseidon_hash_2_native, poseidon_hash_4 as poseidon_hash_4_native,
};
// Import gadgets for R1CS
use crate::gadgets::poseidon::{poseidon_hash_2, poseidon_hash_4};
use crate::Bn254Fr;

// ============================================================================
// Note Commitment
// ============================================================================

/// Computes a note commitment (native)
///
/// `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
///
/// # Arguments
///
/// * `value` - Token amount in the note
/// * `asset_id` - Token type identifier
/// * `owner_pubkey` - Public key of the note owner
/// * `blinding` - Random blinding factor for hiding
///
/// # Returns
///
/// The note commitment (a field element)
pub fn note_commitment_native(
	value: Bn254Fr,
	asset_id: Bn254Fr,
	owner_pubkey: Bn254Fr,
	blinding: Bn254Fr,
) -> Bn254Fr {
	poseidon_hash_4_native(&[value, asset_id, owner_pubkey, blinding])
}

/// Computes a note commitment (in-circuit)
///
/// Equivalent to circomlib's `NoteCommitment` template.
///
/// # Arguments
///
/// * `cs` - Constraint system reference
/// * `value` - Token amount as a circuit variable
/// * `asset_id` - Token type as a circuit variable
/// * `owner_pubkey` - Owner's public key as a circuit variable
/// * `blinding` - Blinding factor as a circuit variable
///
/// # Returns
///
/// The commitment as a circuit variable
pub fn note_commitment(
	cs: ConstraintSystemRef<Bn254Fr>,
	value: &FpVar<Bn254Fr>,
	asset_id: &FpVar<Bn254Fr>,
	owner_pubkey: &FpVar<Bn254Fr>,
	blinding: &FpVar<Bn254Fr>,
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	poseidon_hash_4(
		cs,
		&[
			value.clone(),
			asset_id.clone(),
			owner_pubkey.clone(),
			blinding.clone(),
		],
	)
}

// ============================================================================
// Nullifier
// ============================================================================

/// Computes a nullifier (native)
///
/// `nullifier = Poseidon(commitment, spending_key)`
///
/// The nullifier uniquely identifies a note being spent. Once revealed,
/// the note cannot be spent again (double-spend prevention).
///
/// # Arguments
///
/// * `commitment` - The note commitment being spent
/// * `spending_key` - Secret key that authorizes spending
///
/// # Returns
///
/// The nullifier (a field element)
pub fn nullifier_native(commitment: Bn254Fr, spending_key: Bn254Fr) -> Bn254Fr {
	poseidon_hash_2_native(&[commitment, spending_key])
}

/// Computes a nullifier (in-circuit)
///
/// Equivalent to circomlib's `Nullifier` template.
///
/// # Arguments
///
/// * `cs` - Constraint system reference
/// * `commitment` - The commitment as a circuit variable
/// * `spending_key` - The spending key as a circuit variable
///
/// # Returns
///
/// The nullifier as a circuit variable
pub fn nullifier(
	cs: ConstraintSystemRef<Bn254Fr>,
	commitment: &FpVar<Bn254Fr>,
	spending_key: &FpVar<Bn254Fr>,
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	poseidon_hash_2(cs, &[commitment.clone(), spending_key.clone()])
}

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
	pub owner_pubkey: Bn254Fr,
	/// Random blinding factor
	pub blinding: Bn254Fr,
}

impl Note {
	/// Creates a new note
	pub fn new(value: u64, asset_id: u64, owner_pubkey: Bn254Fr, blinding: Bn254Fr) -> Self {
		Self {
			value: Bn254Fr::from(value),
			asset_id: Bn254Fr::from(asset_id),
			owner_pubkey,
			blinding,
		}
	}

	/// Computes the commitment for this note
	pub fn commitment(&self) -> Bn254Fr {
		note_commitment_native(self.value, self.asset_id, self.owner_pubkey, self.blinding)
	}

	/// Computes the nullifier for this note
	pub fn nullifier(&self, spending_key: Bn254Fr) -> Bn254Fr {
		nullifier_native(self.commitment(), spending_key)
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
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
	use ark_relations::r1cs::ConstraintSystem;

	#[test]
	fn test_note_commitment_native() {
		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);

		let commitment1 = note_commitment_native(value, asset_id, owner, blinding);
		let commitment2 = note_commitment_native(value, asset_id, owner, blinding);

		// Deterministic
		assert_eq!(commitment1, commitment2);

		// Different blinding = different commitment
		let blinding2 = Bn254Fr::from(99999u64);
		let commitment3 = note_commitment_native(value, asset_id, owner, blinding2);
		assert_ne!(commitment1, commitment3);
	}

	#[test]
	fn test_nullifier_native() {
		let commitment = Bn254Fr::from(123456u64);
		let spending_key = Bn254Fr::from(789012u64);

		let nf1 = nullifier_native(commitment, spending_key);
		let nf2 = nullifier_native(commitment, spending_key);

		// Same inputs = same nullifier
		assert_eq!(nf1, nf2);

		// Different spending key = different nullifier
		let spending_key2 = Bn254Fr::from(111111u64);
		let nf3 = nullifier_native(commitment, spending_key2);
		assert_ne!(nf1, nf3);
	}

	#[test]
	fn test_note_commitment_circuit() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = Bn254Fr::from(500u64);
		let asset_id = Bn254Fr::from(2u64);
		let owner = Bn254Fr::from(54321u64);
		let blinding = Bn254Fr::from(98765u64);

		// Allocate circuit variables
		let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(asset_id)).unwrap();
		let owner_var = FpVar::new_witness(cs.clone(), || Ok(owner)).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(blinding)).unwrap();

		// Compute commitment in circuit
		let commitment_var = note_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&owner_var,
			&blinding_var,
		)
		.unwrap();

		// Compute expected commitment
		let expected = note_commitment_native(value, asset_id, owner, blinding);

		// Verify
		assert!(cs.is_satisfied().unwrap());
		assert_eq!(commitment_var.value().unwrap(), expected);
	}

	#[test]
	fn test_note_struct() {
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);
		let spending_key = Bn254Fr::from(11111u64);

		let note = Note::new(1000, 1, owner, blinding);

		// Commitment should be deterministic
		let c1 = note.commitment();
		let c2 = note.commitment();
		assert_eq!(c1, c2);

		// Nullifier
		let nf = note.nullifier(spending_key);
		let expected_nf = nullifier_native(c1, spending_key);
		assert_eq!(nf, expected_nf);
	}

	#[test]
	fn test_note_zero() {
		let zero_note = Note::zero();

		assert_eq!(zero_note.value, Bn254Fr::from(0u64));
		assert_eq!(zero_note.asset_id, Bn254Fr::from(0u64));

		// Zero note should still have a valid (non-zero) commitment
		let commitment = zero_note.commitment();
		// Poseidon of zeros is not zero
		assert_ne!(commitment, Bn254Fr::from(0u64));
	}
}
