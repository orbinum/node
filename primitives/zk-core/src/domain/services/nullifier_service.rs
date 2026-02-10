//! Nullifier Service
//!
//! Domain service for computing nullifiers that prevent double-spending.

use crate::domain::{
	ports::PoseidonHasher,
	value_objects::{Commitment, Nullifier, SpendingKey},
};

/// Domain service for computing nullifiers
///
/// Computes: `nullifier = Poseidon(commitment, spending_key)`
pub struct NullifierService<H: PoseidonHasher> {
	hasher: H,
}

impl<H: PoseidonHasher> NullifierService<H> {
	/// Create a new nullifier service with the given hasher
	pub fn new(hasher: H) -> Self {
		Self { hasher }
	}

	/// Compute the nullifier for a commitment
	///
	/// Hashes the commitment with the spending key to create a unique
	/// identifier that marks the note as spent.
	pub fn compute_nullifier(
		&self,
		commitment: &Commitment,
		spending_key: &SpendingKey,
	) -> Nullifier {
		let inputs = [commitment.inner(), spending_key.inner()];

		let hash = self.hasher.hash_2(inputs);
		Nullifier::from(hash)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::domain::{ports::PoseidonHasher, value_objects::FieldElement};
	use ark_bn254::Fr;
	extern crate alloc;

	use alloc::vec::Vec;

	// ===== Mock Hashers =====

	struct MockHasherConstant;

	impl PoseidonHasher for MockHasherConstant {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	struct MockHasherSum;

	impl PoseidonHasher for MockHasherSum {
		fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from(inputs[0].inner() + inputs[1].inner())
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	struct MockHasherFirst;

	impl PoseidonHasher for MockHasherFirst {
		fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
			inputs[0]
		}

		fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
			inputs[0]
		}
	}

	// ===== Service Construction Tests =====

	#[test]
	fn test_new() {
		let hasher = MockHasherConstant;
		let _service = NullifierService::new(hasher);
	}

	#[test]
	fn test_new_with_different_hasher() {
		let hasher = MockHasherSum;
		let _service = NullifierService::new(hasher);
	}

	// ===== Compute Nullifier Basic Tests =====

	#[test]
	fn test_compute_nullifier() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(42));
	}

	#[test]
	fn test_compute_nullifier_zero_commitment() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(0u64));
		let spending_key = SpendingKey::from(Fr::from(100u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(42));
	}

	#[test]
	fn test_compute_nullifier_zero_key() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(0u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(42));
	}

	#[test]
	fn test_compute_nullifier_both_zero() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(0u64));
		let spending_key = SpendingKey::from(Fr::from(0u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(42));
	}

	#[test]
	fn test_compute_nullifier_max_values() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(u64::MAX));
		let spending_key = SpendingKey::from(Fr::from(u64::MAX));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(42));
	}

	// ===== Determinism Tests =====

	#[test]
	fn test_compute_nullifier_deterministic() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let nullifier1 = service.compute_nullifier(&commitment, &spending_key);
		let nullifier2 = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier1, nullifier2);
	}

	#[test]
	fn test_compute_nullifier_deterministic_sum_hasher() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let nullifier1 = service.compute_nullifier(&commitment, &spending_key);
		let nullifier2 = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier1, nullifier2);
	}

	#[test]
	fn test_compute_nullifier_multiple_calls() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(123u64));
		let spending_key = SpendingKey::from(Fr::from(456u64));
		let nullifiers: Vec<_> = (0..10)
			.map(|_| service.compute_nullifier(&commitment, &spending_key))
			.collect();
		for nullifier in &nullifiers[1..] {
			assert_eq!(nullifier, &nullifiers[0]);
		}
	}

	// ===== Sum Hasher Tests =====

	#[test]
	fn test_compute_nullifier_sum_hasher() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		// Sum: 100 + 200 = 300
		assert_eq!(nullifier.inner(), FieldElement::from_u64(300));
	}

	#[test]
	fn test_compute_nullifier_sum_hasher_zero_commitment() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(0u64));
		let spending_key = SpendingKey::from(Fr::from(100u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(100));
	}

	#[test]
	fn test_compute_nullifier_sum_hasher_zero_key() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(0u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(100));
	}

	// ===== Different Keys Tests =====

	#[test]
	fn test_different_keys_sum_hasher() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let key1 = SpendingKey::from(Fr::from(200u64));
		let key2 = SpendingKey::from(Fr::from(300u64));
		let n1 = service.compute_nullifier(&commitment, &key1);
		let n2 = service.compute_nullifier(&commitment, &key2);
		// Different keys produce different nullifiers: 300 vs 400
		assert_ne!(n1, n2);
	}

	#[test]
	fn test_different_commitments_same_key() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment1 = Commitment::from(Fr::from(100u64));
		let commitment2 = Commitment::from(Fr::from(200u64));
		let spending_key = SpendingKey::from(Fr::from(50u64));
		let n1 = service.compute_nullifier(&commitment1, &spending_key);
		let n2 = service.compute_nullifier(&commitment2, &spending_key);
		// Different commitments produce different nullifiers: 150 vs 250
		assert_ne!(n1, n2);
	}

	#[test]
	fn test_different_everything() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment1 = Commitment::from(Fr::from(100u64));
		let commitment2 = Commitment::from(Fr::from(200u64));
		let key1 = SpendingKey::from(Fr::from(10u64));
		let key2 = SpendingKey::from(Fr::from(20u64));
		let n1 = service.compute_nullifier(&commitment1, &key1);
		let n2 = service.compute_nullifier(&commitment2, &key2);
		// 110 vs 220
		assert_ne!(n1, n2);
	}

	// ===== First Hasher Tests =====

	#[test]
	fn test_compute_nullifier_first_hasher() {
		let hasher = MockHasherFirst;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		// Returns first input (commitment)
		assert_eq!(nullifier.inner(), commitment.inner());
	}

	#[test]
	fn test_compute_nullifier_first_hasher_changes_with_commitment() {
		let hasher = MockHasherFirst;
		let service = NullifierService::new(hasher);
		let commitment1 = Commitment::from(Fr::from(100u64));
		let commitment2 = Commitment::from(Fr::from(200u64));
		let spending_key = SpendingKey::from(Fr::from(50u64));
		let n1 = service.compute_nullifier(&commitment1, &spending_key);
		let n2 = service.compute_nullifier(&commitment2, &spending_key);
		assert_ne!(n1, n2);
	}

	#[test]
	fn test_compute_nullifier_first_hasher_ignores_key() {
		let hasher = MockHasherFirst;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let key1 = SpendingKey::from(Fr::from(200u64));
		let key2 = SpendingKey::from(Fr::from(300u64));
		let n1 = service.compute_nullifier(&commitment, &key1);
		let n2 = service.compute_nullifier(&commitment, &key2);
		// MockHasherFirst only uses first input (commitment)
		assert_eq!(n1, n2);
	}

	// ===== Service Reuse Tests =====

	#[test]
	fn test_service_reuse() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment1 = Commitment::from(Fr::from(100u64));
		let commitment2 = Commitment::from(Fr::from(200u64));
		let key1 = SpendingKey::from(Fr::from(10u64));
		let key2 = SpendingKey::from(Fr::from(20u64));
		let _n1 = service.compute_nullifier(&commitment1, &key1);
		let _n2 = service.compute_nullifier(&commitment2, &key2);
		let _n3 = service.compute_nullifier(&commitment1, &key2);
		let _n4 = service.compute_nullifier(&commitment2, &key1);
	}

	#[test]
	fn test_service_reference() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let service_ref = &service;
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let nullifier = service_ref.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(42));
	}

	#[test]
	fn test_multiple_services_same_hasher_type() {
		let hasher1 = MockHasherConstant;
		let hasher2 = MockHasherConstant;
		let service1 = NullifierService::new(hasher1);
		let service2 = NullifierService::new(hasher2);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let n1 = service1.compute_nullifier(&commitment, &spending_key);
		let n2 = service2.compute_nullifier(&commitment, &spending_key);
		assert_eq!(n1, n2);
	}

	// ===== Edge Cases =====

	#[test]
	fn test_compute_nullifier_large_values() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(1_000_000u64));
		let spending_key = SpendingKey::from(Fr::from(2_000_000u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(3_000_000));
	}

	#[test]
	fn test_compute_nullifier_sequential_values() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let nullifiers: Vec<_> = (0..10)
			.map(|i| {
				let commitment = Commitment::from(Fr::from(i));
				let spending_key = SpendingKey::from(Fr::from(100u64));
				service.compute_nullifier(&commitment, &spending_key)
			})
			.collect();
		// Each nullifier should be different: 100, 101, 102, ...
		for i in 0..nullifiers.len() - 1 {
			assert_ne!(nullifiers[i], nullifiers[i + 1]);
		}
	}

	#[test]
	fn test_compute_nullifier_same_sum_different_inputs() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment1 = Commitment::from(Fr::from(100u64));
		let key1 = SpendingKey::from(Fr::from(200u64));
		let commitment2 = Commitment::from(Fr::from(200u64));
		let key2 = SpendingKey::from(Fr::from(100u64));
		let n1 = service.compute_nullifier(&commitment1, &key1);
		let n2 = service.compute_nullifier(&commitment2, &key2);
		// MockHasherSum: both sum to 300
		assert_eq!(n1, n2);
	}

	// ===== Trait Tests =====

	#[test]
	fn test_nullifier_equality() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let n1 = service.compute_nullifier(&commitment, &spending_key);
		let n2 = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(n1, n2);
	}

	#[test]
	fn test_nullifier_inner() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(50u64));
		let spending_key = SpendingKey::from(Fr::from(75u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier.inner(), FieldElement::from_u64(125));
	}

	#[test]
	fn test_nullifier_from_field_element() {
		let hasher = MockHasherConstant;
		let service = NullifierService::new(hasher);
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let nullifier = service.compute_nullifier(&commitment, &spending_key);
		let field_element = nullifier.inner();
		let nullifier2 = Nullifier::from(field_element);
		assert_eq!(nullifier, nullifier2);
	}

	// ===== Collection Tests =====

	#[test]
	fn test_compute_multiple_nullifiers_in_vector() {
		let hasher = MockHasherSum;
		let service = NullifierService::new(hasher);
		let commitments = [
			Commitment::from(Fr::from(100u64)),
			Commitment::from(Fr::from(200u64)),
			Commitment::from(Fr::from(300u64)),
		];
		let spending_key = SpendingKey::from(Fr::from(50u64));
		let nullifiers: Vec<_> = commitments
			.iter()
			.map(|c| service.compute_nullifier(c, &spending_key))
			.collect();
		assert_eq!(nullifiers.len(), 3);
		assert_eq!(nullifiers[0].inner(), FieldElement::from_u64(150));
		assert_eq!(nullifiers[1].inner(), FieldElement::from_u64(250));
		assert_eq!(nullifiers[2].inner(), FieldElement::from_u64(350));
	}

	#[test]
	fn test_compute_nullifier_different_hasher_implementations() {
		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));
		let service_constant = NullifierService::new(MockHasherConstant);
		let service_sum = NullifierService::new(MockHasherSum);
		let service_first = NullifierService::new(MockHasherFirst);
		let n1 = service_constant.compute_nullifier(&commitment, &spending_key);
		let n2 = service_sum.compute_nullifier(&commitment, &spending_key);
		let n3 = service_first.compute_nullifier(&commitment, &spending_key);
		// Different hasher implementations produce different results
		assert_eq!(n1.inner(), FieldElement::from_u64(42)); // Constant
		assert_eq!(n2.inner(), FieldElement::from_u64(300)); // Sum
		assert_eq!(n3.inner(), commitment.inner()); // First
	}
}
