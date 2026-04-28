//! Native Poseidon Hash Functions
//!
//! Thin wrappers over `orbinum-zk-core` for use in gadgets and circuit tests.
//! Converts between `ark_bn254::Fr` and `zk-core`'s `FieldElement` wrapper.

use ark_bn254::Fr;
use orbinum_zk_core::{hash::PoseidonHasher, FieldElement, LightPoseidonHasher};

/// Poseidon hash for 2 field elements
pub(crate) fn poseidon_hash_2(inputs: &[Fr; 2]) -> Fr {
	let hasher = LightPoseidonHasher;
	let field_inputs = [FieldElement::new(inputs[0]), FieldElement::new(inputs[1])];
	hasher.hash_2(field_inputs).inner()
}

/// Poseidon hash for 4 field elements
pub(crate) fn poseidon_hash_4(inputs: &[Fr; 4]) -> Fr {
	let hasher = LightPoseidonHasher;
	let field_inputs = [
		FieldElement::new(inputs[0]),
		FieldElement::new(inputs[1]),
		FieldElement::new(inputs[2]),
		FieldElement::new(inputs[3]),
	];
	hasher.hash_4(field_inputs).inner()
}

/// Poseidon hash for 5 field elements (used by EdDSA-Poseidon challenge: Poseidon5(R8x, R8y, Ax, Ay, msg))
pub(crate) fn poseidon_hash_5(inputs: &[Fr; 5]) -> Fr {
	let hasher = LightPoseidonHasher;
	let field_inputs = [
		FieldElement::new(inputs[0]),
		FieldElement::new(inputs[1]),
		FieldElement::new(inputs[2]),
		FieldElement::new(inputs[3]),
		FieldElement::new(inputs[4]),
	];
	hasher.hash_5(field_inputs).inner()
}

/// Poseidon hash for variable-length inputs (2, 4, or 5 supported)
pub(crate) fn poseidon_hash(inputs: &[Fr]) -> Result<Fr, &'static str> {
	if inputs.is_empty() || inputs.len() > 16 {
		return Err("Invalid input length");
	}
	match inputs.len() {
		2 => Ok(poseidon_hash_2(&[inputs[0], inputs[1]])),
		4 => Ok(poseidon_hash_4(&[
			inputs[0], inputs[1], inputs[2], inputs[3],
		])),
		5 => Ok(poseidon_hash_5(&[
			inputs[0], inputs[1], inputs[2], inputs[3], inputs[4],
		])),
		_ => Err("Only 2, 4, or 5 inputs supported"),
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
			Fr::from(1u64),
			Fr::from(1u64),
			Fr::from(1u64),
			Fr::from(1u64),
		];
		let result = poseidon_hash_4(&inputs);
		assert_ne!(result, Fr::from(0u64));
	}

	// ===== poseidon_hash (var) Tests =====

	#[test]
	fn test_poseidon_hash_var_two_inputs() {
		let inputs = vec![Fr::from(1u64), Fr::from(2u64)];
		let result = poseidon_hash(&inputs);
		assert!(result.is_ok());
		assert_ne!(result.unwrap(), Fr::from(0u64));
	}

	#[test]
	fn test_poseidon_hash_var_four_inputs() {
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
	fn test_poseidon_hash_var_empty() {
		let inputs: Vec<Fr> = vec![];
		let result = poseidon_hash(&inputs);
		assert!(result.is_err());
	}

	#[test]
	fn test_poseidon_hash_var_one_input() {
		let inputs = vec![Fr::from(1u64)];
		let result = poseidon_hash(&inputs);
		assert!(result.is_err());
	}

	#[test]
	fn test_poseidon_hash_var_three_inputs() {
		let inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
		let result = poseidon_hash(&inputs);
		assert!(result.is_err());
	}

	#[test]
	fn test_poseidon_hash_var_matches_direct_2() {
		let inputs = vec![Fr::from(10u64), Fr::from(20u64)];
		let direct = poseidon_hash_2(&[inputs[0], inputs[1]]);
		let var_result = poseidon_hash(&inputs).unwrap();
		assert_eq!(direct, var_result);
	}

	#[test]
	fn test_poseidon_hash_var_matches_direct_4() {
		let inputs = vec![
			Fr::from(1u64),
			Fr::from(2u64),
			Fr::from(3u64),
			Fr::from(4u64),
		];
		let direct = poseidon_hash_4(&[inputs[0], inputs[1], inputs[2], inputs[3]]);
		let var_result = poseidon_hash(&inputs).unwrap();
		assert_eq!(direct, var_result);
	}
}
