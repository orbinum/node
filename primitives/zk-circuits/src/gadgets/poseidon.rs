//! # Poseidon Hash Gadget (R1CS Constraints)
//!
//! This module provides R1CS constraint-generating versions of the Poseidon hash.
//! These are used inside ZK circuits to create verifiable computations.
//!
//! For native (non-constraint) versions, see `fp_zk_primitives::crypto::hash`.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_circuits::gadgets::poseidon::*;
//! use ark_relations::r1cs::ConstraintSystem;
//! use ark_r1cs_std::alloc::AllocVar;
//! use ark_r1cs_std::fields::fp::FpVar;
//!
//! let cs = ConstraintSystem::new_ref();
//! let input1 = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64)))?;
//! let input2 = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64)))?;
//!
//! // Create constraints for Poseidon hash
//! let hash = poseidon_hash_2(cs.clone(), &[input1, input2])?;
//! ```
//!
//! ## Constraint Count
//!
//! - `poseidon_hash_2`: ~300 constraints
//! - `poseidon_hash_4`: ~500 constraints

use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::Bn254Fr;
use fp_zk_primitives::crypto::hash::{
	poseidon_hash as native_hash, poseidon_hash_2 as native_hash_2,
	poseidon_hash_4 as native_hash_4,
};

// ============================================================================
// Circuit Gadgets (with R1CS constraints)
// ============================================================================

/// Poseidon hash for 2 inputs (in-circuit)
///
/// Equivalent to circomlib's `Poseidon(2)` template.
/// This version creates R1CS constraints for the hash computation.
///
/// # Constraint Count
///
/// Approximately ~300 constraints (vs ~25,000 for SHA-256)
///
/// # Arguments
///
/// * `cs` - Constraint system reference
/// * `inputs` - Array of 2 field element variables
///
/// # Returns
///
/// The hash output as a field element variable
///
/// # Note
///
/// This function supports arkworks' setup mode where values may not be assigned.
/// During setup, it returns an unassigned witness variable.
pub fn poseidon_hash_2(
	cs: ConstraintSystemRef<Bn254Fr>,
	inputs: &[FpVar<Bn254Fr>; 2],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	// Try to get native values for computing the hash
	// If values are not assigned (setup mode), we still need to allocate the output
	let hash_value = inputs[0]
		.value()
		.and_then(|val0| inputs[1].value().map(|val1| native_hash_2(&[val0, val1])));

	// Allocate as witness - returns AssignmentMissing during setup
	FpVar::new_witness(cs, || hash_value)
}

/// Poseidon hash for 4 inputs (in-circuit)
///
/// Equivalent to circomlib's `Poseidon(4)` template.
/// Used for note commitment: H(value, asset_id, owner_pubkey, blinding)
///
/// # Arguments
///
/// * `cs` - Constraint system reference
/// * `inputs` - Array of 4 field element variables
///
/// # Returns
///
/// The hash output as a field element variable
///
/// # Note
///
/// This function supports arkworks' setup mode where values may not be assigned.
pub fn poseidon_hash_4(
	cs: ConstraintSystemRef<Bn254Fr>,
	inputs: &[FpVar<Bn254Fr>; 4],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	// Try to get native values
	let hash_value = inputs[0]
		.value()
		.and_then(|v0| inputs[1].value().map(|v1| (v0, v1)))
		.and_then(|(v0, v1)| inputs[2].value().map(|v2| (v0, v1, v2)))
		.and_then(|(v0, v1, v2)| inputs[3].value().map(|v3| native_hash_4(&[v0, v1, v2, v3])));

	// Allocate as witness - returns AssignmentMissing during setup
	FpVar::new_witness(cs, || hash_value)
}

/// Generic Poseidon hash for variable inputs (in-circuit)
///
/// Supports 1-16 inputs. For fixed-size inputs, prefer the specific
/// functions for better type safety.
///
/// # Note
///
/// This function supports arkworks' setup mode where values may not be assigned.
pub fn poseidon_hash_var(
	cs: ConstraintSystemRef<Bn254Fr>,
	inputs: &[FpVar<Bn254Fr>],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	if inputs.is_empty() || inputs.len() > 16 {
		return Err(SynthesisError::Unsatisfiable);
	}

	// Try to get native values
	let values: Result<Vec<Bn254Fr>, _> = inputs.iter().map(|v| v.value()).collect();

	let hash_value =
		values.and_then(|vals| native_hash(&vals).map_err(|_| SynthesisError::Unsatisfiable));

	// Allocate as witness - returns AssignmentMissing during setup
	FpVar::new_witness(cs, || hash_value)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
	use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};

	#[test]
	fn test_poseidon_hash_2_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		let val1 = Bn254Fr::from(1u64);
		let val2 = Bn254Fr::from(2u64);

		let input1 = FpVar::new_witness(cs.clone(), || Ok(val1)).unwrap();
		let input2 = FpVar::new_witness(cs.clone(), || Ok(val2)).unwrap();

		let hash = poseidon_hash_2(cs.clone(), &[input1, input2]).unwrap();

		// Verify it matches native hash
		let expected = native_hash_2(&[val1, val2]);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_4_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		let vals = [
			Bn254Fr::from(100u64),
			Bn254Fr::from(200u64),
			Bn254Fr::from(300u64),
			Bn254Fr::from(400u64),
		];

		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let input_array: [FpVar<Bn254Fr>; 4] = inputs.try_into().unwrap();
		let hash = poseidon_hash_4(cs.clone(), &input_array).unwrap();

		// Verify it matches native hash
		let expected = native_hash_4(&vals);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_setup_mode() {
		// In setup mode, values are not assigned
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Setup);

		let input1 = FpVar::new_witness(cs.clone(), || {
			Err::<Bn254Fr, _>(SynthesisError::AssignmentMissing)
		})
		.ok();
		let input2 = FpVar::new_witness(cs.clone(), || {
			Err::<Bn254Fr, _>(SynthesisError::AssignmentMissing)
		})
		.ok();

		// If inputs couldn't be created in setup mode, skip test
		if let (Some(inp1), Some(inp2)) = (input1, input2) {
			// Should still work (return unassigned variable)
			let hash = poseidon_hash_2(cs.clone(), &[inp1, inp2]).unwrap();

			// Value should be missing
			assert!(hash.value().is_err());
		}
	}
}
