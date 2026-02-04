//! Hash Function Port
//!
//! Trait defining hash function interface for the domain layer,
//! enabling independence from specific implementations.

use crate::domain::value_objects::FieldElement;

/// Port for Poseidon hash functions
///
/// Defines domain requirements for hash functions without depending
/// on specific implementations (light-poseidon, circom, etc.).
pub trait PoseidonHasher {
	/// Hash 2 field elements
	///
	/// Used for Merkle tree sibling hashing and nullifier computation.
	fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement;

	/// Hash 4 field elements
	///
	/// Used for note commitments.
	fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement;
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::Fr;

	// ===== Mock Implementations =====

	#[derive(Clone)]
	struct MockHasherZero;

	impl PoseidonHasher for MockHasherZero {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::zero()
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::zero()
		}
	}

	#[derive(Clone)]
	struct MockHasherConstant;

	impl PoseidonHasher for MockHasherConstant {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	#[derive(Clone)]
	struct MockHasherSum;

	impl PoseidonHasher for MockHasherSum {
		fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
			// Simple sum for testing
			FieldElement::from(inputs[0].inner() + inputs[1].inner())
		}

		fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
			// Simple sum for testing
			let sum = inputs[0].inner() + inputs[1].inner() + inputs[2].inner() + inputs[3].inner();
			FieldElement::from(sum)
		}
	}

	#[derive(Clone)]
	struct MockHasherFirst;

	impl PoseidonHasher for MockHasherFirst {
		fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
			inputs[0]
		}

		fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
			inputs[0]
		}
	}

	// ===== Hash2 Tests =====

	#[test]
	fn test_hash_2_zero_hasher() {
		let hasher = MockHasherZero;
		let input1 = FieldElement::from_u64(10);
		let input2 = FieldElement::from_u64(20);
		let result = hasher.hash_2([input1, input2]);
		assert_eq!(result, FieldElement::zero());
	}

	#[test]
	fn test_hash_2_constant_hasher() {
		let hasher = MockHasherConstant;
		let input1 = FieldElement::from_u64(10);
		let input2 = FieldElement::from_u64(20);
		let result = hasher.hash_2([input1, input2]);
		assert_eq!(result, FieldElement::from_u64(42));
	}

	#[test]
	fn test_hash_2_sum_hasher() {
		let hasher = MockHasherSum;
		let input1 = FieldElement::from_u64(10);
		let input2 = FieldElement::from_u64(20);
		let result = hasher.hash_2([input1, input2]);
		assert_eq!(result, FieldElement::from_u64(30));
	}

	#[test]
	fn test_hash_2_first_hasher() {
		let hasher = MockHasherFirst;
		let input1 = FieldElement::from_u64(100);
		let input2 = FieldElement::from_u64(200);
		let result = hasher.hash_2([input1, input2]);
		assert_eq!(result, FieldElement::from_u64(100));
	}

	#[test]
	fn test_hash_2_zero_inputs() {
		let hasher = MockHasherSum;
		let input1 = FieldElement::zero();
		let input2 = FieldElement::zero();
		let result = hasher.hash_2([input1, input2]);
		assert_eq!(result, FieldElement::zero());
	}

	#[test]
	fn test_hash_2_deterministic() {
		let hasher = MockHasherConstant;
		let input1 = FieldElement::from_u64(10);
		let input2 = FieldElement::from_u64(20);
		let result1 = hasher.hash_2([input1, input2]);
		let result2 = hasher.hash_2([input1, input2]);
		assert_eq!(result1, result2);
	}

	#[test]
	fn test_hash_2_large_values() {
		let hasher = MockHasherFirst;
		let input1 = FieldElement::from(Fr::from(u64::MAX));
		let input2 = FieldElement::from(Fr::from(u64::MAX));
		let result = hasher.hash_2([input1, input2]);
		assert_eq!(result, input1);
	}

	#[test]
	fn test_hash_2_different_inputs() {
		let hasher = MockHasherSum;
		let input1a = FieldElement::from_u64(10);
		let input2a = FieldElement::from_u64(20);
		let input1b = FieldElement::from_u64(15);
		let input2b = FieldElement::from_u64(15);
		let result1 = hasher.hash_2([input1a, input2a]);
		let result2 = hasher.hash_2([input1b, input2b]);
		assert_eq!(result1, result2); // Both sum to 30
	}

	// ===== Hash4 Tests =====

	#[test]
	fn test_hash_4_zero_hasher() {
		let hasher = MockHasherZero;
		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];
		let result = hasher.hash_4(inputs);
		assert_eq!(result, FieldElement::zero());
	}

	#[test]
	fn test_hash_4_constant_hasher() {
		let hasher = MockHasherConstant;
		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];
		let result = hasher.hash_4(inputs);
		assert_eq!(result, FieldElement::from_u64(100));
	}

	#[test]
	fn test_hash_4_sum_hasher() {
		let hasher = MockHasherSum;
		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];
		let result = hasher.hash_4(inputs);
		assert_eq!(result, FieldElement::from_u64(10));
	}

	#[test]
	fn test_hash_4_first_hasher() {
		let hasher = MockHasherFirst;
		let inputs = [
			FieldElement::from_u64(99),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];
		let result = hasher.hash_4(inputs);
		assert_eq!(result, FieldElement::from_u64(99));
	}

	#[test]
	fn test_hash_4_zero_inputs() {
		let hasher = MockHasherSum;
		let inputs = [
			FieldElement::zero(),
			FieldElement::zero(),
			FieldElement::zero(),
			FieldElement::zero(),
		];
		let result = hasher.hash_4(inputs);
		assert_eq!(result, FieldElement::zero());
	}

	#[test]
	fn test_hash_4_deterministic() {
		let hasher = MockHasherConstant;
		let inputs = [
			FieldElement::from_u64(10),
			FieldElement::from_u64(20),
			FieldElement::from_u64(30),
			FieldElement::from_u64(40),
		];
		let result1 = hasher.hash_4(inputs);
		let result2 = hasher.hash_4(inputs);
		assert_eq!(result1, result2);
	}

	#[test]
	fn test_hash_4_large_values() {
		let hasher = MockHasherFirst;
		let inputs = [
			FieldElement::from(Fr::from(u64::MAX)),
			FieldElement::from(Fr::from(u64::MAX)),
			FieldElement::from(Fr::from(u64::MAX)),
			FieldElement::from(Fr::from(u64::MAX)),
		];
		let result = hasher.hash_4(inputs);
		assert_eq!(result, inputs[0]);
	}

	#[test]
	fn test_hash_4_mixed_values() {
		let hasher = MockHasherSum;
		let inputs = [
			FieldElement::from_u64(100),
			FieldElement::zero(),
			FieldElement::from_u64(50),
			FieldElement::zero(),
		];
		let result = hasher.hash_4(inputs);
		assert_eq!(result, FieldElement::from_u64(150));
	}

	// ===== Clone Tests =====

	#[test]
	fn test_hasher_clone() {
		let hasher1 = MockHasherConstant;
		let hasher2 = hasher1.clone();
		let input1 = FieldElement::from_u64(10);
		let input2 = FieldElement::from_u64(20);
		let result1 = hasher1.hash_2([input1, input2]);
		let result2 = hasher2.hash_2([input1, input2]);
		assert_eq!(result1, result2);
	}

	#[test]
	fn test_hasher_clone_independence() {
		let hasher1 = MockHasherSum;
		let hasher2 = hasher1.clone();
		let inputs_a = [FieldElement::from_u64(10), FieldElement::from_u64(20)];
		let inputs_b = [FieldElement::from_u64(30), FieldElement::from_u64(40)];
		let result1 = hasher1.hash_2(inputs_a);
		let result2 = hasher2.hash_2(inputs_b);
		assert_eq!(result1, FieldElement::from_u64(30));
		assert_eq!(result2, FieldElement::from_u64(70));
	}

	// ===== Generic Function Tests =====

	fn generic_hash_2<H: PoseidonHasher>(hasher: H) -> FieldElement {
		let input1 = FieldElement::from_u64(1);
		let input2 = FieldElement::from_u64(2);
		hasher.hash_2([input1, input2])
	}

	fn generic_hash_4<H: PoseidonHasher>(hasher: H) -> FieldElement {
		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];
		hasher.hash_4(inputs)
	}

	#[test]
	fn test_generic_hasher_usage_hash_2() {
		let result = generic_hash_2(MockHasherConstant);
		assert_eq!(result, FieldElement::from_u64(42));
	}

	#[test]
	fn test_generic_hasher_usage_hash_4() {
		let result = generic_hash_4(MockHasherConstant);
		assert_eq!(result, FieldElement::from_u64(100));
	}

	#[test]
	fn test_trait_object_compatibility() {
		let hasher: &dyn PoseidonHasher = &MockHasherZero;
		let input1 = FieldElement::from_u64(10);
		let input2 = FieldElement::from_u64(20);
		let result = hasher.hash_2([input1, input2]);
		assert_eq!(result, FieldElement::zero());
	}

	// ===== Multiple Implementations Tests =====

	#[test]
	fn test_different_implementations_hash_2() {
		let input1 = FieldElement::from_u64(10);
		let input2 = FieldElement::from_u64(20);

		let result_zero = MockHasherZero.hash_2([input1, input2]);
		let result_const = MockHasherConstant.hash_2([input1, input2]);
		let result_sum = MockHasherSum.hash_2([input1, input2]);
		let result_first = MockHasherFirst.hash_2([input1, input2]);

		assert_eq!(result_zero, FieldElement::zero());
		assert_eq!(result_const, FieldElement::from_u64(42));
		assert_eq!(result_sum, FieldElement::from_u64(30));
		assert_eq!(result_first, FieldElement::from_u64(10));
	}

	#[test]
	fn test_different_implementations_hash_4() {
		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];

		let result_zero = MockHasherZero.hash_4(inputs);
		let result_const = MockHasherConstant.hash_4(inputs);
		let result_sum = MockHasherSum.hash_4(inputs);
		let result_first = MockHasherFirst.hash_4(inputs);

		assert_eq!(result_zero, FieldElement::zero());
		assert_eq!(result_const, FieldElement::from_u64(100));
		assert_eq!(result_sum, FieldElement::from_u64(10));
		assert_eq!(result_first, FieldElement::from_u64(1));
	}
}
