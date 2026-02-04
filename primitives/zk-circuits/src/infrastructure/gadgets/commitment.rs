//! Commitment Gadget (R1CS Constraints)
//!
//! R1CS constraint-generating versions of commitment and nullifier schemes.
//! Used inside ZK circuits to prove knowledge of commitments without revealing values.

use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::poseidon::{poseidon_hash_2, poseidon_hash_4};
use crate::Bn254Fr;

// ============================================================================
// Circuit Gadgets (with R1CS constraints)
// ============================================================================

/// Create a note commitment (in-circuit)
///
/// Generates R1CS constraints equivalent to native `create_commitment`.
/// Formula: `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
pub fn create_commitment(
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

/// Compute a nullifier from a commitment (in-circuit)
///
/// Generates R1CS constraints equivalent to native `compute_nullifier`.
/// Formula: `nullifier = Poseidon(commitment, spending_key)`
pub fn compute_nullifier(
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
	use orbinum_zk_core::domain::services::{CommitmentService, NullifierService};
	use orbinum_zk_core::domain::value_objects::{
		Blinding, Commitment, FieldElement, OwnerPubkey, SpendingKey,
	};
	extern crate alloc;
	use orbinum_zk_core::infrastructure::crypto::LightPoseidonHasher;

	// ===== create_commitment Tests =====

	#[test]
	fn test_create_commitment_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		// Native values
		let value = 100u64;
		let asset_id = 1u64;
		let pubkey_val = 12345u64;
		let blinding_val = 67890u64;

		// Compute native commitment using service
		let hasher = LightPoseidonHasher;
		let service = CommitmentService::new(hasher);
		let expected = service.create_commitment(
			value,
			asset_id,
			OwnerPubkey::new(FieldElement::from_u64(pubkey_val)),
			Blinding::new(FieldElement::from_u64(blinding_val)),
		);

		// Allocate circuit variables
		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(value))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(asset_id))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(pubkey_val))).unwrap();
		let blinding_var =
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(blinding_val))).unwrap();

		// Create commitment in-circuit
		let commitment = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		// Verify it matches native computation
		assert_eq!(commitment.value().unwrap(), expected.inner().inner());
	}

	#[test]
	fn test_create_commitment_zero_value() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let commitment = create_commitment(
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
	fn test_create_commitment_large_value() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let commitment = create_commitment(
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
	fn test_create_commitment_deterministic() {
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

		let commitment1 =
			create_commitment(cs1, &value_var1, &asset_var1, &pubkey_var1, &blinding_var1).unwrap();

		let commitment2 =
			create_commitment(cs2, &value_var2, &asset_var2, &pubkey_var2, &blinding_var2).unwrap();

		assert_eq!(commitment1.value().unwrap(), commitment2.value().unwrap());
	}

	#[test]
	fn test_create_commitment_different_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let value_var2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let commitment1 = create_commitment(
			cs.clone(),
			&value_var1,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		let commitment2 = create_commitment(
			cs.clone(),
			&value_var2,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		assert_ne!(commitment1.value().unwrap(), commitment2.value().unwrap());
	}

	#[test]
	fn test_create_commitment_different_assets() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset_var1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let asset_var2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let commitment1 = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var1,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		let commitment2 = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var2,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		assert_ne!(commitment1.value().unwrap(), commitment2.value().unwrap());
	}

	#[test]
	fn test_create_commitment_different_pubkeys() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let pubkey_var2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let commitment1 = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var1,
			&blinding_var,
		)
		.unwrap();

		let commitment2 = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var2,
			&blinding_var,
		)
		.unwrap();

		assert_ne!(commitment1.value().unwrap(), commitment2.value().unwrap());
	}

	#[test]
	fn test_create_commitment_different_blinding() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let blinding_var2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(300u64))).unwrap();

		let commitment1 = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var1,
		)
		.unwrap();

		let commitment2 = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var2,
		)
		.unwrap();

		assert_ne!(commitment1.value().unwrap(), commitment2.value().unwrap());
	}

	#[test]
	fn test_create_commitment_constants() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var = FpVar::new_constant(cs.clone(), Bn254Fr::from(100u64)).unwrap();
		let asset_var = FpVar::new_constant(cs.clone(), Bn254Fr::from(1u64)).unwrap();
		let pubkey_var = FpVar::new_constant(cs.clone(), Bn254Fr::from(100u64)).unwrap();
		let blinding_var = FpVar::new_constant(cs.clone(), Bn254Fr::from(200u64)).unwrap();

		let commitment = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		assert_ne!(commitment.value().unwrap(), Bn254Fr::from(0u64));
	}

	// ===== compute_nullifier Tests =====

	#[test]
	fn test_compute_nullifier_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		// Native values
		let commitment_val = Bn254Fr::from(99999u64);
		let spending_key_val = Bn254Fr::from(55555u64);

		// Compute native nullifier
		let commitment = Commitment::new(FieldElement::new(commitment_val));
		let spending_key = SpendingKey::new(FieldElement::new(spending_key_val));
		let hasher = LightPoseidonHasher;
		let service = NullifierService::new(hasher);
		let expected = service.compute_nullifier(&commitment, &spending_key);

		// Allocate circuit variables
		let commitment_var = FpVar::new_witness(cs.clone(), || Ok(commitment_val)).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(spending_key_val)).unwrap();

		// Compute nullifier in-circuit
		let nullifier = compute_nullifier(cs.clone(), &commitment_var, &key_var).unwrap();

		// Verify it matches native computation
		assert_eq!(nullifier.value().unwrap(), expected.inner().inner());
	}

	#[test]
	fn test_compute_nullifier_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment_val = Bn254Fr::from(12345u64);
		let spending_key_val = Bn254Fr::from(67890u64);

		let commitment_var1 = FpVar::new_witness(cs1.clone(), || Ok(commitment_val)).unwrap();
		let key_var1 = FpVar::new_witness(cs1.clone(), || Ok(spending_key_val)).unwrap();

		let commitment_var2 = FpVar::new_witness(cs2.clone(), || Ok(commitment_val)).unwrap();
		let key_var2 = FpVar::new_witness(cs2.clone(), || Ok(spending_key_val)).unwrap();

		let nullifier1 = compute_nullifier(cs1, &commitment_var1, &key_var1).unwrap();
		let nullifier2 = compute_nullifier(cs2, &commitment_var2, &key_var2).unwrap();

		assert_eq!(nullifier1.value().unwrap(), nullifier2.value().unwrap());
	}

	#[test]
	fn test_compute_nullifier_different_commitments() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment_var1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let commitment_var2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(300u64))).unwrap();

		let nullifier1 = compute_nullifier(cs.clone(), &commitment_var1, &key_var).unwrap();
		let nullifier2 = compute_nullifier(cs.clone(), &commitment_var2, &key_var).unwrap();

		assert_ne!(nullifier1.value().unwrap(), nullifier2.value().unwrap());
	}

	#[test]
	fn test_compute_nullifier_different_keys() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let key_var1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let key_var2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(300u64))).unwrap();

		let nullifier1 = compute_nullifier(cs.clone(), &commitment_var, &key_var1).unwrap();
		let nullifier2 = compute_nullifier(cs.clone(), &commitment_var, &key_var2).unwrap();

		assert_ne!(nullifier1.value().unwrap(), nullifier2.value().unwrap());
	}

	#[test]
	fn test_compute_nullifier_zero_commitment() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();

		let nullifier = compute_nullifier(cs.clone(), &commitment_var, &key_var).unwrap();

		assert_ne!(nullifier.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_compute_nullifier_zero_key() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap();

		let nullifier = compute_nullifier(cs.clone(), &commitment_var, &key_var).unwrap();

		assert_ne!(nullifier.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_compute_nullifier_large_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment_var =
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX))).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX - 1))).unwrap();

		let nullifier = compute_nullifier(cs.clone(), &commitment_var, &key_var).unwrap();

		assert_ne!(nullifier.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_compute_nullifier_constants() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let commitment_var = FpVar::new_constant(cs.clone(), Bn254Fr::from(100u64)).unwrap();
		let key_var = FpVar::new_constant(cs.clone(), Bn254Fr::from(200u64)).unwrap();

		let nullifier = compute_nullifier(cs.clone(), &commitment_var, &key_var).unwrap();

		assert_ne!(nullifier.value().unwrap(), Bn254Fr::from(0u64));
	}

	// ===== Integration Tests =====

	#[test]
	fn test_commitment_nullifier_integration() {
		let cs = ConstraintSystem::new_ref();

		// Native values
		let value = Bn254Fr::from(500u64);
		let asset_id = Bn254Fr::from(1u64);
		let pubkey = Bn254Fr::from(98765u64);
		let blinding = Bn254Fr::from(43210u64);
		let spending_key = Bn254Fr::from(11111u64);

		// Allocate circuit variables
		let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(asset_id)).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(pubkey)).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(blinding)).unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(spending_key)).unwrap();

		// Create commitment
		let commitment = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		// Compute nullifier from commitment
		let nullifier = compute_nullifier(cs.clone(), &commitment, &key_var).unwrap();

		// Verify native matches circuit - use native crypto helpers
		use crate::infrastructure::native_crypto::{poseidon_hash_2, poseidon_hash_4};

		let native_commitment = poseidon_hash_4(&[value, asset_id, pubkey, blinding]);
		let native_nullifier = poseidon_hash_2(&[native_commitment, spending_key]);

		assert_eq!(commitment.value().unwrap(), native_commitment);
		assert_eq!(nullifier.value().unwrap(), native_nullifier);
	}

	#[test]
	fn test_same_commitment_different_keys_different_nullifiers() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let commitment = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		let key_var1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(300u64))).unwrap();
		let key_var2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(400u64))).unwrap();

		let nullifier1 = compute_nullifier(cs.clone(), &commitment, &key_var1).unwrap();
		let nullifier2 = compute_nullifier(cs.clone(), &commitment, &key_var2).unwrap();

		assert_ne!(nullifier1.value().unwrap(), nullifier2.value().unwrap());
	}

	#[test]
	fn test_different_commitments_same_key_different_nullifiers() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let value_var2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let commitment1 = create_commitment(
			cs.clone(),
			&value_var1,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		let commitment2 = create_commitment(
			cs.clone(),
			&value_var2,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		let key_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(300u64))).unwrap();

		let nullifier1 = compute_nullifier(cs.clone(), &commitment1, &key_var).unwrap();
		let nullifier2 = compute_nullifier(cs.clone(), &commitment2, &key_var).unwrap();

		assert_ne!(nullifier1.value().unwrap(), nullifier2.value().unwrap());
	}

	#[test]
	fn test_commitment_cascade() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let value_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(200u64))).unwrap();

		let commitment1 = create_commitment(
			cs.clone(),
			&value_var,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		// Use commitment1 as input to another commitment
		let commitment2 = create_commitment(
			cs.clone(),
			&commitment1,
			&asset_var,
			&pubkey_var,
			&blinding_var,
		)
		.unwrap();

		assert_ne!(commitment1.value().unwrap(), commitment2.value().unwrap());
	}
}
