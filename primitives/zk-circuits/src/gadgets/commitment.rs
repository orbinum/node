//! # Commitment Gadget (R1CS Constraints)
//!
//! This module provides R1CS constraint-generating versions of commitment and nullifier schemes.
//! These are used inside ZK circuits to prove knowledge of commitments without revealing values.
//!
//! For native (non-constraint) versions, see `fp_zk_primitives::commitment`.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_circuits::gadgets::commitment::*;
//! use ark_r1cs_std::alloc::AllocVar;
//!
//! let cs = ConstraintSystem::new_ref();
//!
//! // Allocate private inputs
//! let value = FpVar::new_witness(cs.clone(), || Ok(Fr::from(100)))?;
//! let asset_id = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1)))?;
//! let pubkey = FpVar::new_witness(cs.clone(), || Ok(pubkey_value))?;
//! let blinding = FpVar::new_witness(cs.clone(), || Ok(blinding_value))?;
//!
//! // Create commitment with constraints
//! let commitment = create_commitment(cs.clone(), &value, &asset_id, &pubkey, &blinding)?;
//! ```

use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::poseidon::{poseidon_hash_2, poseidon_hash_4};
use crate::Bn254Fr;

// ============================================================================
// Circuit Gadgets (with R1CS constraints)
// ============================================================================

/// Create a note commitment (in-circuit)
///
/// Equivalent to the native `create_commitment` but generates R1CS constraints.
///
/// # Arguments
///
/// * `cs` - Constraint system reference
/// * `value` - The amount in the note
/// * `asset_id` - The asset type identifier
/// * `owner_pubkey` - Public key of the note owner
/// * `blinding` - Random blinding factor for hiding
///
/// # Returns
///
/// The commitment hash as a circuit variable
///
/// # Formula
///
/// ```text
/// commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
/// ```
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
/// Equivalent to the native `compute_nullifier` but generates R1CS constraints.
///
/// # Arguments
///
/// * `cs` - Constraint system reference
/// * `commitment` - The note commitment
/// * `spending_key` - Private key used to spend the note
///
/// # Returns
///
/// The nullifier hash as a circuit variable
///
/// # Formula
///
/// ```text
/// nullifier = Poseidon(commitment, spending_key)
/// ```
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
	use fp_zk_primitives::core::types::{Commitment, SpendingKey};
	use fp_zk_primitives::crypto::commitment::{
		compute_nullifier as native_compute_nullifier,
		create_commitment as native_create_commitment,
	};

	#[test]
	fn test_create_commitment_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		// Native values
		let value = Bn254Fr::from(100u64);
		let asset_id = Bn254Fr::from(1u64);
		let pubkey = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);

		// Compute native commitment
		let expected = native_create_commitment(value, asset_id, pubkey, blinding);

		// Allocate circuit variables
		let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
		let asset_var = FpVar::new_witness(cs.clone(), || Ok(asset_id)).unwrap();
		let pubkey_var = FpVar::new_witness(cs.clone(), || Ok(pubkey)).unwrap();
		let blinding_var = FpVar::new_witness(cs.clone(), || Ok(blinding)).unwrap();

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
		assert_eq!(commitment.value().unwrap(), expected.into());
	}

	#[test]
	fn test_compute_nullifier_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		// Native values
		let commitment = Commitment::from(Bn254Fr::from(99999u64));
		let spending_key = SpendingKey::from(Bn254Fr::from(55555u64));

		// Compute native nullifier
		let expected = native_compute_nullifier(&commitment, &spending_key);

		// Allocate circuit variables
		let commitment_var = FpVar::new_witness(cs.clone(), || {
			Ok::<Bn254Fr, SynthesisError>(commitment.into())
		})
		.unwrap();
		let key_var = FpVar::new_witness(cs.clone(), || Ok(spending_key.0)).unwrap();

		// Compute nullifier in-circuit
		let nullifier = compute_nullifier(cs.clone(), &commitment_var, &key_var).unwrap();

		// Verify it matches native computation
		assert_eq!(nullifier.value().unwrap(), expected.into());
	}

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

		// Verify native matches circuit
		let native_commitment = native_create_commitment(value, asset_id, pubkey, blinding);
		let native_nullifier =
			native_compute_nullifier(&native_commitment, &SpendingKey::from(spending_key));

		assert_eq!(commitment.value().unwrap(), native_commitment.into());
		assert_eq!(nullifier.value().unwrap(), native_nullifier.into());
	}
}
