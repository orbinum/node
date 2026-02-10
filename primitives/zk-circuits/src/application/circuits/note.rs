//! Note Commitment and Nullifier Gadgets
//!
//! Core privacy primitives for shielded pool:
//! - Note Commitment: `H(value, asset_id, owner_pubkey, blinding)`
//! - Nullifier: `H(commitment, spending_key)`

use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// Import native functions
use crate::infrastructure::native_crypto::{
	poseidon_hash_2 as poseidon_hash_2_native, poseidon_hash_4 as poseidon_hash_4_native,
};
// Import gadgets for R1CS
use crate::{
	infrastructure::gadgets::poseidon::{poseidon_hash_2, poseidon_hash_4},
	Bn254Fr,
};

// ============================================================================
// Note Commitment
// ============================================================================

/// Computes note commitment (native)
///
/// `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
pub fn note_commitment_native(
	value: Bn254Fr,
	asset_id: Bn254Fr,
	owner_pubkey: Bn254Fr,
	blinding: Bn254Fr,
) -> Bn254Fr {
	poseidon_hash_4_native(&[value, asset_id, owner_pubkey, blinding])
}

/// Computes note commitment (in-circuit)
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
			(*value).clone(),
			(*asset_id).clone(),
			(*owner_pubkey).clone(),
			(*blinding).clone(),
		],
	)
}

// ============================================================================
// Nullifier
// ============================================================================

/// Computes nullifier (native)
///
/// `nullifier = Poseidon(commitment, spending_key)`
pub fn nullifier_native(commitment: Bn254Fr, spending_key: Bn254Fr) -> Bn254Fr {
	poseidon_hash_2_native(&[commitment, spending_key])
}

/// Computes nullifier (in-circuit)
pub fn nullifier(
	cs: ConstraintSystemRef<Bn254Fr>,
	commitment: &FpVar<Bn254Fr>,
	spending_key: &FpVar<Bn254Fr>,
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	poseidon_hash_2(cs, &[(*commitment).clone(), (*spending_key).clone()])
}

// ============================================================================
// Note Structure
// ============================================================================

/// Private note in shielded pool
#[derive(Clone, Debug, PartialEq)]
pub struct Note {
	/// Token amount
	pub value: Bn254Fr,
	/// Token type identifier
	pub asset_id: Bn254Fr,
	/// Public key of owner
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
	extern crate alloc;
	use alloc::{format, vec::Vec};

	// ===== Note Commitment Native Tests =====

	#[test]
	fn test_note_commitment_native_basic() {
		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);

		let commitment = note_commitment_native(value, asset_id, owner, blinding);
		assert_ne!(commitment, Bn254Fr::from(0u64));
	}

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
	fn test_note_commitment_native_deterministic() {
		let value = Bn254Fr::from(500u64);
		let asset_id = Bn254Fr::from(2u64);
		let owner = Bn254Fr::from(54321u64);
		let blinding = Bn254Fr::from(98765u64);

		let commitments: Vec<_> = (0..5)
			.map(|_| note_commitment_native(value, asset_id, owner, blinding))
			.collect();

		for commitment in &commitments[1..] {
			assert_eq!(commitment, &commitments[0]);
		}
	}

	#[test]
	fn test_note_commitment_native_zero_value() {
		let value = Bn254Fr::from(0u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let commitment = note_commitment_native(value, asset_id, owner, blinding);
		assert_ne!(commitment, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_note_commitment_native_different_values() {
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let commitment1 = note_commitment_native(Bn254Fr::from(1000u64), asset_id, owner, blinding);
		let commitment2 = note_commitment_native(Bn254Fr::from(2000u64), asset_id, owner, blinding);

		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_note_commitment_native_different_asset_ids() {
		let value = Bn254Fr::from(1000u64);
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let commitment1 = note_commitment_native(value, Bn254Fr::from(1u64), owner, blinding);
		let commitment2 = note_commitment_native(value, Bn254Fr::from(2u64), owner, blinding);

		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_note_commitment_native_different_owners() {
		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let blinding = Bn254Fr::from(200u64);

		let commitment1 = note_commitment_native(value, asset_id, Bn254Fr::from(100u64), blinding);
		let commitment2 = note_commitment_native(value, asset_id, Bn254Fr::from(200u64), blinding);

		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_note_commitment_native_different_blinding() {
		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(100u64);

		let commitment1 = note_commitment_native(value, asset_id, owner, Bn254Fr::from(200u64));
		let commitment2 = note_commitment_native(value, asset_id, owner, Bn254Fr::from(300u64));

		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_note_commitment_native_large_values() {
		let value = Bn254Fr::from(u64::MAX);
		let asset_id = Bn254Fr::from(u64::MAX - 1);
		let owner = Bn254Fr::from(u64::MAX - 2);
		let blinding = Bn254Fr::from(u64::MAX - 3);

		let commitment = note_commitment_native(value, asset_id, owner, blinding);
		assert_ne!(commitment, Bn254Fr::from(0u64));
	}

	// ===== Nullifier Native Tests =====

	#[test]
	fn test_nullifier_native_basic() {
		let commitment = Bn254Fr::from(123456u64);
		let spending_key = Bn254Fr::from(789012u64);

		let nullifier = nullifier_native(commitment, spending_key);
		assert_ne!(nullifier, Bn254Fr::from(0u64));
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
	fn test_nullifier_native_deterministic() {
		let commitment = Bn254Fr::from(123456u64);
		let spending_key = Bn254Fr::from(789012u64);

		let nullifiers: Vec<_> = (0..5)
			.map(|_| nullifier_native(commitment, spending_key))
			.collect();

		for nullifier in &nullifiers[1..] {
			assert_eq!(nullifier, &nullifiers[0]);
		}
	}

	#[test]
	fn test_nullifier_native_different_commitments() {
		let spending_key = Bn254Fr::from(789012u64);

		let nf1 = nullifier_native(Bn254Fr::from(100u64), spending_key);
		let nf2 = nullifier_native(Bn254Fr::from(200u64), spending_key);

		assert_ne!(nf1, nf2);
	}

	#[test]
	fn test_nullifier_native_different_spending_keys() {
		let commitment = Bn254Fr::from(123456u64);

		let nf1 = nullifier_native(commitment, Bn254Fr::from(100u64));
		let nf2 = nullifier_native(commitment, Bn254Fr::from(200u64));

		assert_ne!(nf1, nf2);
	}

	#[test]
	fn test_nullifier_native_zero_commitment() {
		let commitment = Bn254Fr::from(0u64);
		let spending_key = Bn254Fr::from(100u64);

		let nullifier = nullifier_native(commitment, spending_key);
		assert_ne!(nullifier, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_nullifier_native_zero_spending_key() {
		let commitment = Bn254Fr::from(100u64);
		let spending_key = Bn254Fr::from(0u64);

		let nullifier = nullifier_native(commitment, spending_key);
		assert_ne!(nullifier, Bn254Fr::from(0u64));
	}

	// ===== Note Commitment Circuit Tests =====

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
	fn test_note_commitment_circuit_zero_value() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = Bn254Fr::from(0u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(asset_id)).unwrap();
		let owner_var = FpVar::new_witness(cs.clone(), || Ok(owner)).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(blinding)).unwrap();

		let commitment_var = note_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&owner_var,
			&blinding_var,
		)
		.unwrap();

		let expected = note_commitment_native(value, asset_id, owner, blinding);

		assert!(cs.is_satisfied().unwrap());
		assert_eq!(commitment_var.value().unwrap(), expected);
	}

	// ===== Nullifier Circuit Tests =====

	#[test]
	fn test_nullifier_circuit() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment = Bn254Fr::from(123456u64);
		let spending_key = Bn254Fr::from(789012u64);

		let commitment_var = FpVar::new_witness(cs.clone(), || Ok(commitment)).unwrap();
		let spending_key_var = FpVar::new_witness(cs.clone(), || Ok(spending_key)).unwrap();

		let nullifier_var = nullifier(cs.clone(), &commitment_var, &spending_key_var).unwrap();

		let expected = nullifier_native(commitment, spending_key);

		assert!(cs.is_satisfied().unwrap());
		assert_eq!(nullifier_var.value().unwrap(), expected);
	}

	// ===== Note Struct Tests =====

	#[test]
	fn test_note_new() {
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);

		let note = Note::new(1000, 1, owner, blinding);

		assert_eq!(note.value, Bn254Fr::from(1000u64));
		assert_eq!(note.asset_id, Bn254Fr::from(1u64));
		assert_eq!(note.owner_pubkey, owner);
		assert_eq!(note.blinding, blinding);
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
	fn test_note_commitment_method() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let note = Note::new(1000, 1, owner, blinding);
		let commitment = note.commitment();

		let expected =
			note_commitment_native(note.value, note.asset_id, note.owner_pubkey, note.blinding);

		assert_eq!(commitment, expected);
	}

	#[test]
	fn test_note_nullifier_method() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let note = Note::new(1000, 1, owner, blinding);
		let nullifier = note.nullifier(spending_key);

		let expected = nullifier_native(note.commitment(), spending_key);

		assert_eq!(nullifier, expected);
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

	#[test]
	fn test_note_clone() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let note1 = Note::new(1000, 1, owner, blinding);
		let note2 = note1.clone();

		assert_eq!(note1, note2);
		assert_eq!(note1.commitment(), note2.commitment());
	}

	#[test]
	fn test_note_equality() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let note1 = Note::new(1000, 1, owner, blinding);
		let note2 = Note::new(1000, 1, owner, blinding);

		assert_eq!(note1, note2);
	}

	#[test]
	fn test_note_inequality() {
		let owner = Bn254Fr::from(100u64);
		let blinding1 = Bn254Fr::from(200u64);
		let blinding2 = Bn254Fr::from(300u64);

		let note1 = Note::new(1000, 1, owner, blinding1);
		let note2 = Note::new(1000, 1, owner, blinding2);

		assert_ne!(note1, note2);
	}

	#[test]
	fn test_note_debug() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let note = Note::new(1000, 1, owner, blinding);
		let debug_str = format!("{note:?}");

		assert!(debug_str.contains("Note"));
	}

	// ===== Integration Tests =====

	#[test]
	fn test_commitment_and_nullifier_workflow() {
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);
		let spending_key = Bn254Fr::from(11111u64);

		let note = Note::new(1000, 1, owner, blinding);

		// Get commitment
		let commitment = note.commitment();
		assert_ne!(commitment, Bn254Fr::from(0u64));

		// Get nullifier
		let nullifier = note.nullifier(spending_key);
		assert_ne!(nullifier, Bn254Fr::from(0u64));

		// Different notes should have different commitments/nullifiers
		let note2 = Note::new(2000, 1, owner, blinding);
		assert_ne!(note.commitment(), note2.commitment());
	}

	#[test]
	fn test_same_note_different_spending_keys() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let note = Note::new(1000, 1, owner, blinding);

		let nf1 = note.nullifier(Bn254Fr::from(100u64));
		let nf2 = note.nullifier(Bn254Fr::from(200u64));

		assert_ne!(nf1, nf2);
	}

	#[test]
	fn test_circuit_matches_native() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		// Native computation
		let native_commitment = note_commitment_native(value, asset_id, owner, blinding);

		// Circuit computation
		let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(asset_id)).unwrap();
		let owner_var = FpVar::new_witness(cs.clone(), || Ok(owner)).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(blinding)).unwrap();

		let circuit_commitment = note_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&owner_var,
			&blinding_var,
		)
		.unwrap();

		assert_eq!(circuit_commitment.value().unwrap(), native_commitment);
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_nullifier_circuit_matches_native() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment = Bn254Fr::from(123456u64);
		let spending_key = Bn254Fr::from(789012u64);

		// Native computation
		let native_nullifier = nullifier_native(commitment, spending_key);

		// Circuit computation
		let commitment_var = FpVar::new_witness(cs.clone(), || Ok(commitment)).unwrap();
		let spending_key_var = FpVar::new_witness(cs.clone(), || Ok(spending_key)).unwrap();

		let circuit_nullifier = nullifier(cs.clone(), &commitment_var, &spending_key_var).unwrap();

		assert_eq!(circuit_nullifier.value().unwrap(), native_nullifier);
		assert!(cs.is_satisfied().unwrap());
	}

	// ===== Edge Case Tests =====

	#[test]
	fn test_note_max_value() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let note = Note::new(u64::MAX, u64::MAX, owner, blinding);
		let commitment = note.commitment();

		assert_ne!(commitment, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_multiple_notes_unique_commitments() {
		let owner = Bn254Fr::from(100u64);

		let notes: Vec<_> = (0..10)
			.map(|i| Note::new(1000, 1, owner, Bn254Fr::from(i)))
			.collect();

		let commitments: Vec<_> = notes.iter().map(|n| n.commitment()).collect();

		// All commitments should be unique
		for i in 0..commitments.len() {
			for j in (i + 1)..commitments.len() {
				assert_ne!(commitments[i], commitments[j]);
			}
		}
	}
}
