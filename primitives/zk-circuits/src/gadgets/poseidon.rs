//! Poseidon Hash Gadgets (R1CS Constraints)
//!
//! R1CS constraint-generating Poseidon hash functions for ZK circuits.
//! ~300 constraints for hash_2, ~500 for hash_4 (vs ~25,000 for SHA-256).
//!
//! Use these inside `ConstraintSynthesizer::generate_constraints` implementations.
//! For native (non-circuit) hashing, use `crate::native`.

use alloc::vec::Vec;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::Bn254Fr;

/// Poseidon hash for 2 inputs (in-circuit, R1CS)
///
/// Equivalent to circomlib's `Poseidon(2)`. Supports setup mode.
pub fn poseidon_hash_2(
	cs: ConstraintSystemRef<Bn254Fr>,
	inputs: &[FpVar<Bn254Fr>; 2],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	let hash_value = inputs[0].value().and_then(|v0| {
		inputs[1]
			.value()
			.map(|v1| crate::native::poseidon_hash_2(&[v0, v1]))
	});
	FpVar::new_witness(cs, || hash_value)
}

/// Poseidon hash for 4 inputs (in-circuit, R1CS)
///
/// Equivalent to circomlib's `Poseidon(4)`. Used for note commitments.
pub fn poseidon_hash_4(
	cs: ConstraintSystemRef<Bn254Fr>,
	inputs: &[FpVar<Bn254Fr>; 4],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	let hash_value = inputs[0]
		.value()
		.and_then(|v0| inputs[1].value().map(|v1| (v0, v1)))
		.and_then(|(v0, v1)| inputs[2].value().map(|v2| (v0, v1, v2)))
		.and_then(|(v0, v1, v2)| {
			inputs[3]
				.value()
				.map(|v3| crate::native::poseidon_hash_4(&[v0, v1, v2, v3]))
		});
	FpVar::new_witness(cs, || hash_value)
}

/// Generic Poseidon hash for 1-16 inputs (in-circuit, R1CS)
///
/// Prefer typed variants (`poseidon_hash_2`, `poseidon_hash_4`) for safety.
pub fn poseidon_hash_var(
	cs: ConstraintSystemRef<Bn254Fr>,
	inputs: &[FpVar<Bn254Fr>],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	if inputs.is_empty() || inputs.len() > 16 {
		return Err(SynthesisError::Unsatisfiable);
	}

	let values: Result<Vec<Bn254Fr>, _> = inputs.iter().map(|v| v.value()).collect();
	let hash_value = values.and_then(|vals| {
		crate::native::poseidon_hash(vals.as_slice()).map_err(|_| SynthesisError::Unsatisfiable)
	});

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
	extern crate alloc;
	use alloc::vec;

	// ===== poseidon_hash_2 Tests =====

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

		let expected = crate::native::poseidon_hash_2(&[val1, val2]);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_2_zero_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let val1 = Bn254Fr::from(0u64);
		let val2 = Bn254Fr::from(0u64);
		let input1 = FpVar::new_witness(cs.clone(), || Ok(val1)).unwrap();
		let input2 = FpVar::new_witness(cs.clone(), || Ok(val2)).unwrap();
		let hash = poseidon_hash_2(cs.clone(), &[input1, input2]).unwrap();
		assert_ne!(hash.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_2_deterministic() {
		let val1 = Bn254Fr::from(10u64);
		let val2 = Bn254Fr::from(20u64);

		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();

		let i1a = FpVar::new_witness(cs1.clone(), || Ok(val1)).unwrap();
		let i2a = FpVar::new_witness(cs1.clone(), || Ok(val2)).unwrap();
		let i1b = FpVar::new_witness(cs2.clone(), || Ok(val1)).unwrap();
		let i2b = FpVar::new_witness(cs2.clone(), || Ok(val2)).unwrap();

		let h1 = poseidon_hash_2(cs1, &[i1a, i2a]).unwrap();
		let h2 = poseidon_hash_2(cs2, &[i1b, i2b]).unwrap();
		assert_eq!(h1.value().unwrap(), h2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_2_different_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let i1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let i2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap();
		let i3 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3u64))).unwrap();
		let i4 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(4u64))).unwrap();
		let h1 = poseidon_hash_2(cs.clone(), &[i1, i2]).unwrap();
		let h2 = poseidon_hash_2(cs.clone(), &[i3, i4]).unwrap();
		assert_ne!(h1.value().unwrap(), h2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_2_matches_native() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let val1 = Bn254Fr::from(42u64);
		let val2 = Bn254Fr::from(99u64);
		let i1 = FpVar::new_witness(cs.clone(), || Ok(val1)).unwrap();
		let i2 = FpVar::new_witness(cs.clone(), || Ok(val2)).unwrap();
		let circuit_hash = poseidon_hash_2(cs, &[i1, i2]).unwrap();
		let native_hash = crate::native::poseidon_hash_2(&[val1, val2]);
		assert_eq!(circuit_hash.value().unwrap(), native_hash);
	}

	// ===== poseidon_hash_4 Tests =====

	#[test]
	fn test_poseidon_hash_4_gadget() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Prove {
			construct_matrices: true,
		});

		let vals = [
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		];
		let inputs = vals.map(|v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap());
		let hash = poseidon_hash_4(cs.clone(), &inputs).unwrap();
		let expected = crate::native::poseidon_hash_4(&vals);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_4_deterministic() {
		let vals = [
			Bn254Fr::from(10u64),
			Bn254Fr::from(20u64),
			Bn254Fr::from(30u64),
			Bn254Fr::from(40u64),
		];
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs1 = vals.map(|v| FpVar::new_witness(cs1.clone(), || Ok(v)).unwrap());
		let inputs2 = vals.map(|v| FpVar::new_witness(cs2.clone(), || Ok(v)).unwrap());
		let h1 = poseidon_hash_4(cs1, &inputs1).unwrap();
		let h2 = poseidon_hash_4(cs2, &inputs2).unwrap();
		assert_eq!(h1.value().unwrap(), h2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_4_different_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let v1s = [
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		];
		let v2s = [
			Bn254Fr::from(5u64),
			Bn254Fr::from(6u64),
			Bn254Fr::from(7u64),
			Bn254Fr::from(8u64),
		];
		let inputs1 = v1s.map(|v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap());
		let inputs2 = v2s.map(|v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap());
		let h1 = poseidon_hash_4(cs.clone(), &inputs1).unwrap();
		let h2 = poseidon_hash_4(cs.clone(), &inputs2).unwrap();
		assert_ne!(h1.value().unwrap(), h2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_4_matches_native() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let vals = [
			Bn254Fr::from(100u64),
			Bn254Fr::from(200u64),
			Bn254Fr::from(300u64),
			Bn254Fr::from(400u64),
		];
		let inputs = vals.map(|v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap());
		let circuit_hash = poseidon_hash_4(cs, &inputs).unwrap();
		let native_hash = crate::native::poseidon_hash_4(&vals);
		assert_eq!(circuit_hash.value().unwrap(), native_hash);
	}

	// ===== poseidon_hash_var Tests =====

	#[test]
	fn test_poseidon_hash_var_two_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = vec![
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
		];
		let hash = poseidon_hash_var(cs.clone(), &inputs).unwrap();
		assert_ne!(hash.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_var_four_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = vec![
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(4u64))).unwrap(),
		];
		let hash = poseidon_hash_var(cs.clone(), &inputs).unwrap();
		assert_ne!(hash.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_var_empty_fails() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let result = poseidon_hash_var(cs, &[]);
		assert!(result.is_err());
	}

	#[test]
	fn test_poseidon_hash_var_matches_hash_2() {
		let val1 = Bn254Fr::from(10u64);
		let val2 = Bn254Fr::from(20u64);
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs_var = vec![
			FpVar::new_witness(cs1.clone(), || Ok(val1)).unwrap(),
			FpVar::new_witness(cs1.clone(), || Ok(val2)).unwrap(),
		];
		let i1 = FpVar::new_witness(cs2.clone(), || Ok(val1)).unwrap();
		let i2 = FpVar::new_witness(cs2.clone(), || Ok(val2)).unwrap();
		let h_var = poseidon_hash_var(cs1, &inputs_var).unwrap();
		let h_2 = poseidon_hash_2(cs2, &[i1, i2]).unwrap();
		assert_eq!(h_var.value().unwrap(), h_2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_var_setup_mode() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Setup);
		let inputs = vec![
			FpVar::new_witness(cs.clone(), || {
				Err::<Bn254Fr, _>(SynthesisError::AssignmentMissing)
			})
			.unwrap(),
			FpVar::new_witness(cs.clone(), || {
				Err::<Bn254Fr, _>(SynthesisError::AssignmentMissing)
			})
			.unwrap(),
		];
		// In setup mode it should still allocate a variable
		let result = poseidon_hash_var(cs, &inputs);
		assert!(result.is_ok());
	}
}
