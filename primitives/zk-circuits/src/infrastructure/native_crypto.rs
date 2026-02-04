//! Native Crypto Helpers
//!
//! Convenient function-based access to native crypto operations.

use orbinum_zk_core::{
	domain::{ports::PoseidonHasher, value_objects::FieldElement},
	infrastructure::crypto::LightPoseidonHasher,
};

use ark_bn254::Fr;

/// Hash 2 field elements using native Poseidon
pub fn poseidon_hash_2(inputs: &[Fr; 2]) -> Fr {
	let hasher = LightPoseidonHasher;
	let field_inputs = [FieldElement::new(inputs[0]), FieldElement::new(inputs[1])];
	hasher.hash_2(field_inputs).inner()
}

/// Hash 4 field elements using native Poseidon
pub fn poseidon_hash_4(inputs: &[Fr; 4]) -> Fr {
	let hasher = LightPoseidonHasher;
	let field_inputs = [
		FieldElement::new(inputs[0]),
		FieldElement::new(inputs[1]),
		FieldElement::new(inputs[2]),
		FieldElement::new(inputs[3]),
	];
	hasher.hash_4(field_inputs).inner()
}

/// Generic hash for variable-length inputs
pub fn poseidon_hash(inputs: &[Fr]) -> Result<Fr, &'static str> {
	if inputs.is_empty() || inputs.len() > 16 {
		return Err("Invalid input length");
	}

	match inputs.len() {
		2 => Ok(poseidon_hash_2(&[inputs[0], inputs[1]])),
		4 => Ok(poseidon_hash_4(&[
			inputs[0], inputs[1], inputs[2], inputs[3],
		])),
		_ => Err("Only 2 or 4 inputs supported in MVP"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::{vec, vec::Vec};

	// ===== poseidon_hash_2 Tests =====

	#[test]
	fn test_poseidon_hash_2_basic() {
		let inputs = [Fr::from(1u64), Fr::from(2u64)];
		let result = poseidon_hash_2(&inputs);

		// Should return a valid field element
		assert_ne!(result, Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_2_deterministic() {
		let inputs = [Fr::from(10u64), Fr::from(20u64)];
		let result1 = poseidon_hash_2(&inputs);
		let result2 = poseidon_hash_2(&inputs);

		assert_eq!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_2_different_inputs() {
		let inputs1 = [Fr::from(1u64), Fr::from(2u64)];
		let inputs2 = [Fr::from(3u64), Fr::from(4u64)];

		let result1 = poseidon_hash_2(&inputs1);
		let result2 = poseidon_hash_2(&inputs2);

		assert_ne!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_2_zero_inputs() {
		let inputs = [Fr::from(0u64), Fr::from(0u64)];
		let result = poseidon_hash_2(&inputs);

		// Even zero inputs should produce a valid hash
		assert_ne!(result, Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_2_large_values() {
		let inputs = [Fr::from(u64::MAX), Fr::from(u64::MAX - 1)];
		let result = poseidon_hash_2(&inputs);

		assert_ne!(result, Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_2_order_matters() {
		let inputs1 = [Fr::from(1u64), Fr::from(2u64)];
		let inputs2 = [Fr::from(2u64), Fr::from(1u64)];

		let result1 = poseidon_hash_2(&inputs1);
		let result2 = poseidon_hash_2(&inputs2);

		// Different order should produce different hash
		assert_ne!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_2_collision_resistance() {
		let inputs1 = [Fr::from(100u64), Fr::from(200u64)];
		let inputs2 = [Fr::from(101u64), Fr::from(200u64)];

		let result1 = poseidon_hash_2(&inputs1);
		let result2 = poseidon_hash_2(&inputs2);

		assert_ne!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_2_same_value_twice() {
		let inputs = [Fr::from(42u64), Fr::from(42u64)];
		let result = poseidon_hash_2(&inputs);

		assert_ne!(result, Fr::from(0u64));
	}

	// ===== poseidon_hash_4 Tests =====

	#[test]
	fn test_poseidon_hash_4_basic() {
		let inputs = [
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
		];
		let result = poseidon_hash_4(&inputs);

		assert_ne!(result, Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_4_deterministic() {
		let inputs = [
			Fr::from(10u64),
			Fr::from(20u64),
			Fr::from(30u64),
			Fr::from(40u64),
		];
		let result1 = poseidon_hash_4(&inputs);
		let result2 = poseidon_hash_4(&inputs);

		assert_eq!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_4_different_inputs() {
		let inputs1 = [
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
		];
		let inputs2 = [
			Fr::from(5u64),
			Fr::from(6u64),
			Fr::from(7u64),
			Fr::from(8u64),
		];

		let result1 = poseidon_hash_4(&inputs1);
		let result2 = poseidon_hash_4(&inputs2);

		assert_ne!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_4_zero_inputs() {
		let inputs = [
			Fr::from(0u64),
			Fr::from(0u64),
			Fr::from(0u64),
			Fr::from(0u64),
		];
		let result = poseidon_hash_4(&inputs);

		assert_ne!(result, Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_4_large_values() {
		let inputs = [
			Fr::from(u64::MAX),
			Fr::from(u64::MAX - 1),
			Fr::from(u64::MAX - 2),
			Fr::from(u64::MAX - 3),
		];
		let result = poseidon_hash_4(&inputs);

		assert_ne!(result, Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_4_order_matters() {
		let inputs1 = [
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
		];
		let inputs2 = [
			Fr::from(4u64),
			Fr::from(3u64),
			Fr::from(2u64),
			Fr::from(1u64),
		];

		let result1 = poseidon_hash_4(&inputs1);
		let result2 = poseidon_hash_4(&inputs2);

		assert_ne!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_4_collision_resistance() {
		let inputs1 = [
			Fr::from(100u64),
			Fr::from(200u64),
			Fr::from(300u64),
			Fr::from(400u64),
		];
		let inputs2 = [
			Fr::from(101u64),
			Fr::from(200u64),
			Fr::from(300u64),
			Fr::from(400u64),
		];

		let result1 = poseidon_hash_4(&inputs1);
		let result2 = poseidon_hash_4(&inputs2);

		assert_ne!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_4_same_values() {
		let inputs = [
			Fr::from(42u64),
			Fr::from(42u64),
			Fr::from(42u64),
			Fr::from(42u64),
		];
		let result = poseidon_hash_4(&inputs);

		assert_ne!(result, Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_4_mixed_values() {
		let inputs = [
			Fr::from(0u64),
			Fr::from(1u64),
			Fr::from(u64::MAX),
			Fr::from(42u64),
		];
		let result = poseidon_hash_4(&inputs);

		assert_ne!(result, Fr::from(0u64));
	}

	// ===== poseidon_hash (generic) Tests =====

	#[test]
	fn test_poseidon_hash_2_inputs() {
		let inputs = vec![Fr::from(1u64), Fr::from(2u64)];
		let result = poseidon_hash(&inputs);

		assert!(result.is_ok());
		assert_ne!(result.unwrap(), Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_4_inputs() {
		let inputs = vec![
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
		];
		let result = poseidon_hash(&inputs);

		assert!(result.is_ok());
		assert_ne!(result.unwrap(), Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_empty_inputs() {
		let inputs: Vec<Fr> = vec![];
		let result = poseidon_hash(&inputs);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Invalid input length");
	}

	#[test]
	fn test_poseidon_hash_too_many_inputs() {
		let inputs: Vec<Fr> = (0..17).map(Fr::from).collect();
		let result = poseidon_hash(&inputs);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Invalid input length");
	}

	#[test]
	fn test_poseidon_hash_1_input_unsupported() {
		let inputs = vec![Fr::from(42u64)];
		let result = poseidon_hash(&inputs);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Only 2 or 4 inputs supported in MVP");
	}

	#[test]
	fn test_poseidon_hash_3_inputs_unsupported() {
		let inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
		let result = poseidon_hash(&inputs);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Only 2 or 4 inputs supported in MVP");
	}

	#[test]
	fn test_poseidon_hash_5_inputs_unsupported() {
		let inputs = vec![
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
			Fr::from(5u64),
		];
		let result = poseidon_hash(&inputs);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Only 2 or 4 inputs supported in MVP");
	}

	#[test]
	fn test_poseidon_hash_deterministic() {
		let inputs = vec![Fr::from(10u64), Fr::from(20u64)];
		let result1 = poseidon_hash(&inputs).unwrap();
		let result2 = poseidon_hash(&inputs).unwrap();

		assert_eq!(result1, result2);
	}

	#[test]
	fn test_poseidon_hash_matches_hash_2() {
		let inputs_vec = vec![Fr::from(10u64), Fr::from(20u64)];
		let inputs_arr = [Fr::from(10u64), Fr::from(20u64)];

		let result_generic = poseidon_hash(&inputs_vec).unwrap();
		let result_specific = poseidon_hash_2(&inputs_arr);

		assert_eq!(result_generic, result_specific);
	}

	#[test]
	fn test_poseidon_hash_matches_hash_4() {
		let inputs_vec = vec![
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
		];
		let inputs_arr = [
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
		];

		let result_generic = poseidon_hash(&inputs_vec).unwrap();
		let result_specific = poseidon_hash_4(&inputs_arr);

		assert_eq!(result_generic, result_specific);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_all_functions_produce_different_results() {
		let inputs_2 = [Fr::from(1u64), Fr::from(2u64)];
		let inputs_4 = [
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
		];

		let result_2 = poseidon_hash_2(&inputs_2);
		let result_4 = poseidon_hash_4(&inputs_4);

		// Different arity should produce different hashes
		assert_ne!(result_2, result_4);
	}

	#[test]
	fn test_hash_2_cascade() {
		let a = Fr::from(1u64);
		let b = Fr::from(2u64);
		let c = Fr::from(3u64);

		// Hash(a, b) then hash that result with c
		let hash_ab = poseidon_hash_2(&[a, b]);
		let hash_abc = poseidon_hash_2(&[hash_ab, c]);

		assert_ne!(hash_abc, Fr::from(0u64));
		assert_ne!(hash_abc, hash_ab);
	}

	#[test]
	fn test_multiple_hashes_with_same_hasher() {
		let inputs1 = [Fr::from(1u64), Fr::from(2u64)];
		let inputs2 = [Fr::from(3u64), Fr::from(4u64)];
		let inputs3 = [Fr::from(5u64), Fr::from(6u64)];

		let result1 = poseidon_hash_2(&inputs1);
		let result2 = poseidon_hash_2(&inputs2);
		let result3 = poseidon_hash_2(&inputs3);

		// All should be different
		assert_ne!(result1, result2);
		assert_ne!(result2, result3);
		assert_ne!(result1, result3);
	}
}
