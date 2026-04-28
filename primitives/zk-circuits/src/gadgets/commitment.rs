//! Commitment and Nullifier Gadgets (R1CS Constraints)
//!
//! R1CS constraint-generating versions of commitment and nullifier schemes.
//! Used inside ZK circuits to prove knowledge of notes without revealing values.
//!
//! - `note_commitment`: `Poseidon(value, asset_id, owner_pubkey, blinding)`
//! - `nullifier`: `Poseidon(commitment, spending_key)`

use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::poseidon::{poseidon_hash_2, poseidon_hash_4};
use crate::Bn254Fr;

/// Compute note commitment (in-circuit, R1CS)
///
/// `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
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

/// Compute nullifier (in-circuit, R1CS)
///
/// `nullifier = Poseidon(commitment, spending_key)`
pub fn nullifier(
	cs: ConstraintSystemRef<Bn254Fr>,
	commitment: &FpVar<Bn254Fr>,
	spending_key: &FpVar<Bn254Fr>,
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	poseidon_hash_2(cs, &[commitment.clone(), spending_key.clone()])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
	use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
	use orbinum_zk_core::LightPoseidonHasher;
	use orbinum_zk_core::{
		ops::{compute_commitment as ops_commitment, compute_nullifier as ops_nullifier},
		Blinding, Commitment, FieldElement, OwnerPubkey, SpendingKey,
	};

	// ===== note_commitment Tests =====

	#[test]
	fn test_note_commitment_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		let value = 100u64;
		let asset_id = 1u64;
		let pubkey_val = 12345u64;
		let blinding_val = 67890u64;

		let hasher = LightPoseidonHasher;
		let expected = ops_commitment(
			&hasher,
			value,
			asset_id,
			OwnerPubkey::from(FieldElement::from_u64(pubkey_val)),
			Blinding::from(FieldElement::from_u64(blinding_val)),
		);

		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(value))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(asset_id))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(pubkey_val))).unwrap();
		let blinding_var =
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(blinding_val))).unwrap();

		let commitment = note_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		assert_eq!(commitment.value().unwrap(), expected.inner().inner());
	}

	#[test]
	fn test_note_commitment_zero_value() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let commitment = note_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();
		assert_ne!(commitment.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_note_commitment_large_value() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let commitment = note_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();
		assert_ne!(commitment.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_note_commitment_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = Bn254Fr::from(100u64);
		let asset_id = Bn254Fr::from(1u64);
		let pubkey = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let value_var1 = FpVar::new_witness(cs1.clone(), || Ok(value)).unwrap();
		let asset_var1 = FpVar::new_witness(cs1.clone(), || Ok(asset_id)).unwrap();
		let pubkey_var1 = FpVar::new_witness(cs1.clone(), || Ok(pubkey)).unwrap();
		let blinding_var1 = FpVar::new_witness(cs1.clone(), || Ok(blinding)).unwrap();

		let value_var2 = FpVar::new_witness(cs2.clone(), || Ok(value)).unwrap();
		let asset_var2 = FpVar::new_witness(cs2.clone(), || Ok(asset_id)).unwrap();
		let pubkey_var2 = FpVar::new_witness(cs2.clone(), || Ok(pubkey)).unwrap();
		let blinding_var2 = FpVar::new_witness(cs2.clone(), || Ok(blinding)).unwrap();

		let c1 =
			note_commitment(cs1, &value_var1, &asset_var1, &pubkey_var1, &blinding_var1).unwrap();
		let c2 =
			note_commitment(cs2, &value_var2, &asset_var2, &pubkey_var2, &blinding_var2).unwrap();

		assert_eq!(c1.value().unwrap(), c2.value().unwrap());
	}

	#[test]
	fn test_note_commitment_different_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let value2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let asset = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let c1 = note_commitment(cs.clone(), &value1, &asset, &pubkey, &blinding).unwrap();
		let c2 = note_commitment(cs.clone(), &value2, &asset, &pubkey, &blinding).unwrap();

		assert_ne!(c1.value().unwrap(), c2.value().unwrap());
	}

	#[test]
	fn test_note_commitment_different_assets() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let asset2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap();
		let pubkey = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let c1 = note_commitment(cs.clone(), &value, &asset1, &pubkey, &blinding).unwrap();
		let c2 = note_commitment(cs.clone(), &value, &asset2, &pubkey, &blinding).unwrap();

		assert_ne!(c1.value().unwrap(), c2.value().unwrap());
	}

	#[test]
	fn test_note_commitment_different_pubkeys() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let pubkey2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let blinding = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let c1 = note_commitment(cs.clone(), &value, &asset, &pubkey1, &blinding).unwrap();
		let c2 = note_commitment(cs.clone(), &value, &asset, &pubkey2, &blinding).unwrap();

		assert_ne!(c1.value().unwrap(), c2.value().unwrap());
	}

	#[test]
	fn test_note_commitment_different_blinding() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let blinding2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(300u64))).unwrap();

		let c1 = note_commitment(cs.clone(), &value, &asset, &pubkey, &blinding1).unwrap();
		let c2 = note_commitment(cs.clone(), &value, &asset, &pubkey, &blinding2).unwrap();

		assert_ne!(c1.value().unwrap(), c2.value().unwrap());
	}

	#[test]
	fn test_note_commitment_constants() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = FpVar::new_constant(cs.clone(), Bn254Fr::from(100u64)).unwrap();
		let asset = FpVar::new_constant(cs.clone(), Bn254Fr::from(1u64)).unwrap();
		let pubkey = FpVar::new_constant(cs.clone(), Bn254Fr::from(100u64)).unwrap();
		let blinding = FpVar::new_constant(cs.clone(), Bn254Fr::from(200u64)).unwrap();

		let commitment = note_commitment(cs.clone(), &value, &asset, &pubkey, &blinding).unwrap();

		assert_ne!(commitment.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_note_commitment_circuit_matches_native() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);

		let native_commitment =
			crate::types::note_commitment_native(value, asset_id, owner, blinding);

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

		assert!(cs.is_satisfied().unwrap());
		assert_eq!(circuit_commitment.value().unwrap(), native_commitment);
	}

	// ===== nullifier Tests =====

	#[test]
	fn test_nullifier_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		let commitment_val = Bn254Fr::from(99999u64);
		let spending_key_val = Bn254Fr::from(55555u64);

		// Use zk-core ops for expected value
		let commitment_inner = Commitment::new(FieldElement::new(commitment_val));
		let spending_key_inner = SpendingKey::new(FieldElement::new(spending_key_val));
		let hasher = LightPoseidonHasher;
		let expected = ops_nullifier(&hasher, commitment_inner, spending_key_inner);

		let commitment_var = FpVar::new_witness(cs.clone(), || Ok(commitment_val)).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(spending_key_val)).unwrap();

		let nf = nullifier(cs.clone(), &commitment_var, &key_var).unwrap();

		assert_eq!(nf.value().unwrap(), expected.inner().inner());
	}

	#[test]
	fn test_nullifier_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment_val = Bn254Fr::from(12345u64);
		let spending_key_val = Bn254Fr::from(67890u64);

		let c1 = FpVar::new_witness(cs1.clone(), || Ok(commitment_val)).unwrap();
		let k1 = FpVar::new_witness(cs1.clone(), || Ok(spending_key_val)).unwrap();
		let c2 = FpVar::new_witness(cs2.clone(), || Ok(commitment_val)).unwrap();
		let k2 = FpVar::new_witness(cs2.clone(), || Ok(spending_key_val)).unwrap();

		let nf1 = nullifier(cs1, &c1, &k1).unwrap();
		let nf2 = nullifier(cs2, &c2, &k2).unwrap();

		assert_eq!(nf1.value().unwrap(), nf2.value().unwrap());
	}

	#[test]
	fn test_nullifier_different_commitments() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let c1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let c2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let key = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(300u64))).unwrap();

		let nf1 = nullifier(cs.clone(), &c1, &key).unwrap();
		let nf2 = nullifier(cs.clone(), &c2, &key).unwrap();

		assert_ne!(nf1.value().unwrap(), nf2.value().unwrap());
	}

	#[test]
	fn test_nullifier_different_keys() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let key1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let key2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(300u64))).unwrap();

		let nf1 = nullifier(cs.clone(), &commitment, &key1).unwrap();
		let nf2 = nullifier(cs.clone(), &commitment, &key2).unwrap();

		assert_ne!(nf1.value().unwrap(), nf2.value().unwrap());
	}

	#[test]
	fn test_nullifier_zero_commitment() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let commitment = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap();
		let key = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let nf = nullifier(cs.clone(), &commitment, &key).unwrap();
		assert_ne!(nf.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_nullifier_large_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let commitment = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX))).unwrap();
		let key = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX - 1))).unwrap();
		let nf = nullifier(cs.clone(), &commitment, &key).unwrap();
		assert_ne!(nf.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_nullifier_circuit_matches_native() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment = Bn254Fr::from(123456u64);
		let spending_key = Bn254Fr::from(789012u64);

		let commitment_var = FpVar::new_witness(cs.clone(), || Ok(commitment)).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(spending_key)).unwrap();

		let nf_var = nullifier(cs.clone(), &commitment_var, &key_var).unwrap();
		let expected = crate::types::nullifier_native(commitment, spending_key);

		assert!(cs.is_satisfied().unwrap());
		assert_eq!(nf_var.value().unwrap(), expected);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_commitment_nullifier_integration() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = Bn254Fr::from(500u64);
		let asset_id = Bn254Fr::from(1u64);
		let pubkey = Bn254Fr::from(98765u64);
		let blinding = Bn254Fr::from(43210u64);
		let spending_key = Bn254Fr::from(11111u64);

		let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(asset_id)).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(pubkey)).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(blinding)).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(spending_key)).unwrap();

		let commitment = note_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();
		let nf = nullifier(cs.clone(), &commitment, &key_var).unwrap();

		let native_commitment =
			crate::native::poseidon_hash_4(&[value, asset_id, pubkey, blinding]);
		let native_nullifier = crate::native::poseidon_hash_2(&[native_commitment, spending_key]);

		assert_eq!(commitment.value().unwrap(), native_commitment);
		assert_eq!(nf.value().unwrap(), native_nullifier);
	}

	#[test]
	fn test_same_commitment_different_keys_different_nullifiers() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let key1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(111u64))).unwrap();
		let key2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(222u64))).unwrap();

		let commitment = note_commitment(cs.clone(), &value, &asset, &pubkey, &blinding).unwrap();
		let nf1 = nullifier(cs.clone(), &commitment, &key1).unwrap();
		let nf2 = nullifier(cs.clone(), &commitment, &key2).unwrap();

		assert_ne!(nf1.value().unwrap(), nf2.value().unwrap());
	}
}
