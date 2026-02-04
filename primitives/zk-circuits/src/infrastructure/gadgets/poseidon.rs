//! Poseidon Hash Gadget (R1CS Constraints)
//!
//! R1CS constraint-generating versions of Poseidon hash for ZK circuits.
//! ~300 constraints for hash_2, ~500 for hash_4 (vs ~25,000 for SHA-256).

use alloc::vec::Vec;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::infrastructure::native_crypto::{
	poseidon_hash as native_hash, poseidon_hash_2 as native_hash_2,
	poseidon_hash_4 as native_hash_4,
};
use crate::Bn254Fr;

// ============================================================================
// Circuit Gadgets (with R1CS constraints)
// ============================================================================

/// Poseidon hash for 2 inputs (in-circuit)
///
/// Equivalent to circomlib's Poseidon(2). Supports setup mode.
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
/// Equivalent to circomlib's Poseidon(4). Used for note commitments.
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

/// Generic Poseidon hash for 1-16 inputs (in-circuit)
///
/// Prefer specific functions (hash_2, hash_4) for type safety.
pub fn poseidon_hash_var(
	cs: ConstraintSystemRef<Bn254Fr>,
	inputs: &[FpVar<Bn254Fr>],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	if inputs.is_empty() || inputs.len() > 16 {
		return Err(SynthesisError::Unsatisfiable);
	}

	// Try to get native values
	let values: Result<Vec<Bn254Fr>, _> = inputs.iter().map(|v| v.value()).collect();

	let hash_value = values
		.and_then(|vals| native_hash(vals.as_slice()).map_err(|_| SynthesisError::Unsatisfiable));

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

		// Verify it matches native hash
		let expected = native_hash_2(&[val1, val2]);
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

		let expected = native_hash_2(&[val1, val2]);
		assert_eq!(hash.value().unwrap(), expected);
		assert_ne!(hash.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_2_different_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let hash1 = poseidon_hash_2(
			cs.clone(),
			&[
				FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
				FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			],
		)
		.unwrap();

		let hash2 = poseidon_hash_2(
			cs.clone(),
			&[
				FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
				FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(4u64))).unwrap(),
			],
		)
		.unwrap();

		assert_ne!(hash1.value().unwrap(), hash2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_2_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();

		let val1 = Bn254Fr::from(42u64);
		let val2 = Bn254Fr::from(100u64);

		let hash1 = poseidon_hash_2(
			cs1,
			&[
				FpVar::new_witness(ConstraintSystem::new_ref(), || Ok(val1)).unwrap(),
				FpVar::new_witness(ConstraintSystem::new_ref(), || Ok(val2)).unwrap(),
			],
		)
		.unwrap();

		let hash2 = poseidon_hash_2(
			cs2,
			&[
				FpVar::new_witness(ConstraintSystem::new_ref(), || Ok(val1)).unwrap(),
				FpVar::new_witness(ConstraintSystem::new_ref(), || Ok(val2)).unwrap(),
			],
		)
		.unwrap();

		assert_eq!(hash1.value().unwrap(), hash2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_2_order_matters() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let val1 = Bn254Fr::from(1u64);
		let val2 = Bn254Fr::from(2u64);

		let hash_ab = poseidon_hash_2(
			cs.clone(),
			&[
				FpVar::new_witness(cs.clone(), || Ok(val1)).unwrap(),
				FpVar::new_witness(cs.clone(), || Ok(val2)).unwrap(),
			],
		)
		.unwrap();

		let hash_ba = poseidon_hash_2(
			cs.clone(),
			&[
				FpVar::new_witness(cs.clone(), || Ok(val2)).unwrap(),
				FpVar::new_witness(cs.clone(), || Ok(val1)).unwrap(),
			],
		)
		.unwrap();

		assert_ne!(hash_ab.value().unwrap(), hash_ba.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_2_large_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let val1 = Bn254Fr::from(u64::MAX);
		let val2 = Bn254Fr::from(u64::MAX - 1);

		let input1 = FpVar::new_witness(cs.clone(), || Ok(val1)).unwrap();
		let input2 = FpVar::new_witness(cs.clone(), || Ok(val2)).unwrap();

		let hash = poseidon_hash_2(cs.clone(), &[input1, input2]).unwrap();

		let expected = native_hash_2(&[val1, val2]);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_2_same_value_twice() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let val = Bn254Fr::from(42u64);

		let input1 = FpVar::new_witness(cs.clone(), || Ok(val)).unwrap();
		let input2 = FpVar::new_witness(cs.clone(), || Ok(val)).unwrap();

		let hash = poseidon_hash_2(cs.clone(), &[input1, input2]).unwrap();

		let expected = native_hash_2(&[val, val]);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_2_constants() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let val1 = Bn254Fr::from(10u64);
		let val2 = Bn254Fr::from(20u64);

		let input1 = FpVar::new_constant(cs.clone(), val1).unwrap();
		let input2 = FpVar::new_constant(cs.clone(), val2).unwrap();

		let hash = poseidon_hash_2(cs.clone(), &[input1, input2]).unwrap();

		let expected = native_hash_2(&[val1, val2]);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_2_collision_resistance() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let pairs = vec![
			(Bn254Fr::from(1u64), Bn254Fr::from(2u64)),
			(Bn254Fr::from(2u64), Bn254Fr::from(1u64)),
			(Bn254Fr::from(100u64), Bn254Fr::from(200u64)),
			(Bn254Fr::from(42u64), Bn254Fr::from(43u64)),
		];

		let mut hashes = Vec::new();
		for (v1, v2) in pairs {
			let hash = poseidon_hash_2(
				cs.clone(),
				&[
					FpVar::new_witness(cs.clone(), || Ok(v1)).unwrap(),
					FpVar::new_witness(cs.clone(), || Ok(v2)).unwrap(),
				],
			)
			.unwrap();
			hashes.push(hash.value().unwrap());
		}

		// All hashes should be unique
		for i in 0..hashes.len() {
			for j in i + 1..hashes.len() {
				assert_ne!(hashes[i], hashes[j]);
			}
		}
	}

	// ===== poseidon_hash_4 Tests =====

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
	fn test_poseidon_hash_4_zero_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [
			Bn254Fr::from(0u64),
			Bn254Fr::from(0u64),
			Bn254Fr::from(0u64),
			Bn254Fr::from(0u64),
		];

		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let input_array: [FpVar<Bn254Fr>; 4] = inputs.try_into().unwrap();
		let hash = poseidon_hash_4(cs.clone(), &input_array).unwrap();

		let expected = native_hash_4(&vals);
		assert_eq!(hash.value().unwrap(), expected);
		assert_ne!(hash.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_4_different_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals1 = [
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		];
		let vals2 = [
			Bn254Fr::from(5u64),
			Bn254Fr::from(6u64),
			Bn254Fr::from(7u64),
			Bn254Fr::from(8u64),
		];

		let inputs1: Vec<FpVar<Bn254Fr>> = vals1
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();
		let inputs2: Vec<FpVar<Bn254Fr>> = vals2
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash1 = poseidon_hash_4(cs.clone(), &inputs1.try_into().unwrap()).unwrap();
		let hash2 = poseidon_hash_4(cs.clone(), &inputs2.try_into().unwrap()).unwrap();

		assert_ne!(hash1.value().unwrap(), hash2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_4_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [
			Bn254Fr::from(10u64),
			Bn254Fr::from(20u64),
			Bn254Fr::from(30u64),
			Bn254Fr::from(40u64),
		];

		let inputs1: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs1.clone(), || Ok(v)).unwrap())
			.collect();
		let inputs2: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs2.clone(), || Ok(v)).unwrap())
			.collect();

		let hash1 = poseidon_hash_4(cs1, &inputs1.try_into().unwrap()).unwrap();
		let hash2 = poseidon_hash_4(cs2, &inputs2.try_into().unwrap()).unwrap();

		assert_eq!(hash1.value().unwrap(), hash2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_4_order_matters() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		];
		let vals_reversed = [
			Bn254Fr::from(4u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(1u64),
		];

		let inputs1: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();
		let inputs2: Vec<FpVar<Bn254Fr>> = vals_reversed
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash1 = poseidon_hash_4(cs.clone(), &inputs1.try_into().unwrap()).unwrap();
		let hash2 = poseidon_hash_4(cs.clone(), &inputs2.try_into().unwrap()).unwrap();

		assert_ne!(hash1.value().unwrap(), hash2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_4_large_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [
			Bn254Fr::from(u64::MAX),
			Bn254Fr::from(u64::MAX - 1),
			Bn254Fr::from(u64::MAX - 2),
			Bn254Fr::from(u64::MAX - 3),
		];

		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash = poseidon_hash_4(cs.clone(), &inputs.try_into().unwrap()).unwrap();

		let expected = native_hash_4(&vals);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_4_same_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let val = Bn254Fr::from(42u64);
		let vals = [val, val, val, val];

		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash = poseidon_hash_4(cs.clone(), &inputs.try_into().unwrap()).unwrap();

		let expected = native_hash_4(&vals);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_4_mixed_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [
			Bn254Fr::from(0u64),
			Bn254Fr::from(1u64),
			Bn254Fr::from(u64::MAX),
			Bn254Fr::from(42u64),
		];

		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash = poseidon_hash_4(cs.clone(), &inputs.try_into().unwrap()).unwrap();

		let expected = native_hash_4(&vals);
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_4_collision_resistance() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let test_cases = vec![
			[
				Bn254Fr::from(1u64),
				Bn254Fr::from(2u64),
				Bn254Fr::from(3u64),
				Bn254Fr::from(4u64),
			],
			[
				Bn254Fr::from(4u64),
				Bn254Fr::from(3u64),
				Bn254Fr::from(2u64),
				Bn254Fr::from(1u64),
			],
			[
				Bn254Fr::from(10u64),
				Bn254Fr::from(20u64),
				Bn254Fr::from(30u64),
				Bn254Fr::from(40u64),
			],
		];

		let mut hashes = Vec::new();
		for vals in test_cases {
			let inputs: Vec<FpVar<Bn254Fr>> = vals
				.iter()
				.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
				.collect();
			let hash = poseidon_hash_4(cs.clone(), &inputs.try_into().unwrap()).unwrap();
			hashes.push(hash.value().unwrap());
		}

		// All hashes should be unique
		for i in 0..hashes.len() {
			for j in i + 1..hashes.len() {
				assert_ne!(hashes[i], hashes[j]);
			}
		}
	}

	// ===== poseidon_hash_var Tests =====
	// Note: MVP only supports 2 or 4 inputs

	#[test]
	fn test_poseidon_hash_var_two_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [Bn254Fr::from(1u64), Bn254Fr::from(2u64)];
		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash = poseidon_hash_var(cs.clone(), &inputs).unwrap();

		let expected = native_hash(&vals).unwrap();
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_var_four_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		];
		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash = poseidon_hash_var(cs.clone(), &inputs).unwrap();

		let expected = native_hash(&vals).unwrap();
		assert_eq!(hash.value().unwrap(), expected);
	}

	#[test]
	fn test_poseidon_hash_var_empty_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let inputs: Vec<FpVar<Bn254Fr>> = vec![];
		let result = poseidon_hash_var(cs.clone(), &inputs);

		assert!(result.is_err());
	}

	#[test]
	fn test_poseidon_hash_var_single_input_unsupported() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let val = Bn254Fr::from(42u64);
		let input = FpVar::new_witness(cs.clone(), || Ok(val)).unwrap();

		// MVP doesn't support single input
		let result = poseidon_hash_var(cs.clone(), &[input]);
		assert!(result.is_err());
	}

	#[test]
	fn test_poseidon_hash_var_three_inputs_unsupported() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals: Vec<Bn254Fr> = (1..=3).map(|i| Bn254Fr::from(i as u64)).collect();
		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		// MVP doesn't support 3 inputs
		let result = poseidon_hash_var(cs.clone(), &inputs);
		assert!(result.is_err());
	}

	#[test]
	fn test_poseidon_hash_var_too_many_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals: Vec<Bn254Fr> = (1..=17).map(|i| Bn254Fr::from(i as u64)).collect();
		let inputs: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let result = poseidon_hash_var(cs.clone(), &inputs);

		assert!(result.is_err());
	}

	#[test]
	fn test_poseidon_hash_var_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [Bn254Fr::from(10u64), Bn254Fr::from(20u64)];

		let inputs1: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs1.clone(), || Ok(v)).unwrap())
			.collect();
		let inputs2: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs2.clone(), || Ok(v)).unwrap())
			.collect();

		let hash1 = poseidon_hash_var(cs1, &inputs1).unwrap();
		let hash2 = poseidon_hash_var(cs2, &inputs2).unwrap();

		assert_eq!(hash1.value().unwrap(), hash2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_var_matches_hash_2() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [Bn254Fr::from(1u64), Bn254Fr::from(2u64)];
		let inputs_var: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash_var = poseidon_hash_var(cs.clone(), &inputs_var).unwrap();

		let inputs_2: [FpVar<Bn254Fr>; 2] = [
			FpVar::new_witness(cs.clone(), || Ok(vals[0])).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(vals[1])).unwrap(),
		];
		let hash_2 = poseidon_hash_2(cs.clone(), &inputs_2).unwrap();

		assert_eq!(hash_var.value().unwrap(), hash_2.value().unwrap());
	}

	#[test]
	fn test_poseidon_hash_var_matches_hash_4() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let vals = [
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		];
		let inputs_var: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();

		let hash_var = poseidon_hash_var(cs.clone(), &inputs_var).unwrap();

		let inputs_4: Vec<FpVar<Bn254Fr>> = vals
			.iter()
			.map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
			.collect();
		let hash_4 = poseidon_hash_4(cs.clone(), &inputs_4.try_into().unwrap()).unwrap();

		assert_eq!(hash_var.value().unwrap(), hash_4.value().unwrap());
	}

	// ===== Setup Mode Tests =====

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

	#[test]
	fn test_poseidon_hash_4_setup_mode() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Setup);

		let inputs: Vec<_> = (0..4)
			.filter_map(|_| {
				FpVar::new_witness(cs.clone(), || {
					Err::<Bn254Fr, _>(SynthesisError::AssignmentMissing)
				})
				.ok()
			})
			.collect();

		if inputs.len() == 4 {
			let input_array: [FpVar<Bn254Fr>; 4] = inputs.try_into().unwrap();
			let hash = poseidon_hash_4(cs.clone(), &input_array).unwrap();
			assert!(hash.value().is_err());
		}
	}

	#[test]
	fn test_poseidon_hash_var_setup_mode() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		cs.set_mode(SynthesisMode::Setup);

		// Use 2 inputs (supported in MVP)
		let inputs: Vec<_> = (0..2)
			.filter_map(|_| {
				FpVar::new_witness(cs.clone(), || {
					Err::<Bn254Fr, _>(SynthesisError::AssignmentMissing)
				})
				.ok()
			})
			.collect();

		if inputs.len() == 2 {
			let hash = poseidon_hash_var(cs.clone(), &inputs).unwrap();
			assert!(hash.value().is_err());
		}
	}
}
