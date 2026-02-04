//! Commitment Service
//!
//! Domain service for creating cryptographic commitments from note components.

use crate::domain::ports::PoseidonHasher;
use crate::domain::value_objects::{Blinding, Commitment, FieldElement, OwnerPubkey};

/// Domain service for creating commitments
///
/// Creates cryptographic commitments using Poseidon hash:
/// `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
pub struct CommitmentService<H: PoseidonHasher> {
	hasher: H,
}

impl<H: PoseidonHasher> CommitmentService<H> {
	/// Create a new commitment service with the given hasher
	pub fn new(hasher: H) -> Self {
		Self { hasher }
	}

	/// Create a commitment from note components
	///
	/// Returns a cryptographic commitment to the note data.
	pub fn create_commitment(
		&self,
		value: u64,
		asset_id: u64,
		owner_pubkey: OwnerPubkey,
		blinding: Blinding,
	) -> Commitment {
		let inputs = [
			FieldElement::from_u64(value),
			FieldElement::from_u64(asset_id),
			owner_pubkey.inner(),
			blinding.inner(),
		];

		let hash = self.hasher.hash_4(inputs);
		Commitment::from(hash)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
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
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(0)
		}

		fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
			// Sum all inputs for deterministic but varying output
			let sum = inputs[0].inner() + inputs[1].inner() + inputs[2].inner() + inputs[3].inner();
			FieldElement::from(sum)
		}
	}

	// ===== Service Construction Tests =====

	#[test]
	fn test_new() {
		let hasher = MockHasherConstant;
		let _service = CommitmentService::new(hasher);
	}

	#[test]
	fn test_new_with_different_hasher() {
		let hasher = MockHasherSum;
		let _service = CommitmentService::new(hasher);
	}

	// ===== Create Commitment Tests =====

	#[test]
	fn test_create_commitment() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment = service.create_commitment(50, 0, pubkey, blinding);
		assert_eq!(commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_create_commitment_zero_value() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment = service.create_commitment(0, 0, pubkey, blinding);
		assert_eq!(commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_create_commitment_max_value() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment = service.create_commitment(u64::MAX, u64::MAX, pubkey, blinding);
		assert_eq!(commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_create_commitment_different_asset() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment1 = service.create_commitment(100, 0, pubkey, blinding);
		let commitment2 = service.create_commitment(100, 5, pubkey, blinding);
		// MockHasherConstant returns same value
		assert_eq!(commitment1, commitment2);
	}

	#[test]
	fn test_create_commitment_different_pubkey() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey1 = OwnerPubkey::from(Fr::from(100u64));
		let pubkey2 = OwnerPubkey::from(Fr::from(200u64));
		let blinding = Blinding::from(Fr::from(300u64));
		let commitment1 = service.create_commitment(100, 0, pubkey1, blinding);
		let commitment2 = service.create_commitment(100, 0, pubkey2, blinding);
		// MockHasherConstant returns same value
		assert_eq!(commitment1, commitment2);
	}

	#[test]
	fn test_create_commitment_different_blinding() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding1 = Blinding::from(Fr::from(200u64));
		let blinding2 = Blinding::from(Fr::from(300u64));
		let commitment1 = service.create_commitment(100, 0, pubkey, blinding1);
		let commitment2 = service.create_commitment(100, 0, pubkey, blinding2);
		// MockHasherConstant returns same value
		assert_eq!(commitment1, commitment2);
	}

	// ===== Determinism Tests =====

	#[test]
	fn test_create_commitment_deterministic() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment1 = service.create_commitment(50, 0, pubkey, blinding);
		let commitment2 = service.create_commitment(50, 0, pubkey, blinding);
		assert_eq!(commitment1, commitment2);
	}

	#[test]
	fn test_create_commitment_deterministic_with_sum_hasher() {
		let hasher = MockHasherSum;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(10u64));
		let blinding = Blinding::from(Fr::from(20u64));
		let commitment1 = service.create_commitment(5, 3, pubkey, blinding);
		let commitment2 = service.create_commitment(5, 3, pubkey, blinding);
		assert_eq!(commitment1, commitment2);
	}

	#[test]
	fn test_create_commitment_multiple_calls() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitments: Vec<_> = (0..5)
			.map(|_| service.create_commitment(50, 0, pubkey, blinding))
			.collect();
		for c in &commitments {
			assert_eq!(c, &commitments[0]);
		}
	}

	// ===== Sum Hasher Tests (Varying Output) =====

	#[test]
	fn test_create_commitment_sum_hasher_different_values() {
		let hasher = MockHasherSum;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(10u64));
		let blinding = Blinding::from(Fr::from(20u64));
		let commitment1 = service.create_commitment(5, 0, pubkey, blinding);
		let commitment2 = service.create_commitment(10, 0, pubkey, blinding);
		// Different values should produce different commitments with sum hasher
		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_create_commitment_sum_hasher_different_assets() {
		let hasher = MockHasherSum;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(10u64));
		let blinding = Blinding::from(Fr::from(20u64));
		let commitment1 = service.create_commitment(5, 0, pubkey, blinding);
		let commitment2 = service.create_commitment(5, 5, pubkey, blinding);
		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_create_commitment_sum_hasher_different_pubkeys() {
		let hasher = MockHasherSum;
		let service = CommitmentService::new(hasher);
		let pubkey1 = OwnerPubkey::from(Fr::from(10u64));
		let pubkey2 = OwnerPubkey::from(Fr::from(20u64));
		let blinding = Blinding::from(Fr::from(30u64));
		let commitment1 = service.create_commitment(5, 0, pubkey1, blinding);
		let commitment2 = service.create_commitment(5, 0, pubkey2, blinding);
		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_create_commitment_sum_hasher_different_blindings() {
		let hasher = MockHasherSum;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(10u64));
		let blinding1 = Blinding::from(Fr::from(20u64));
		let blinding2 = Blinding::from(Fr::from(30u64));
		let commitment1 = service.create_commitment(5, 0, pubkey, blinding1);
		let commitment2 = service.create_commitment(5, 0, pubkey, blinding2);
		assert_ne!(commitment1, commitment2);
	}

	// ===== Edge Cases =====

	#[test]
	fn test_create_commitment_all_zeros() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(0u64));
		let blinding = Blinding::from(Fr::from(0u64));
		let commitment = service.create_commitment(0, 0, pubkey, blinding);
		assert_eq!(commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_create_commitment_all_max() {
		let hasher = MockHasherSum;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(u64::MAX));
		let blinding = Blinding::from(Fr::from(u64::MAX));
		let commitment = service.create_commitment(u64::MAX, u64::MAX, pubkey, blinding);
		// Should not panic, returns some commitment
		let zero_commitment = Commitment::from(Fr::from(0u64));
		assert_ne!(commitment, zero_commitment);
	}

	#[test]
	fn test_create_commitment_mixed_values() {
		let hasher = MockHasherSum;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment1 = service.create_commitment(50, 0, pubkey, blinding);
		let commitment2 = service.create_commitment(0, 50, pubkey, blinding);
		// Same sum but different positions, MockHasherSum treats them same
		assert_eq!(commitment1, commitment2);
	}

	// ===== Service Reuse Tests =====

	#[test]
	fn test_service_reuse() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		// Service can be used multiple times
		let _c1 = service.create_commitment(10, 0, pubkey, blinding);
		let _c2 = service.create_commitment(20, 0, pubkey, blinding);
		let _c3 = service.create_commitment(30, 0, pubkey, blinding);
	}

	#[test]
	fn test_service_with_varying_inputs() {
		let hasher = MockHasherSum;
		let service = CommitmentService::new(hasher);
		let mut commitments = Vec::new();
		for i in 0..10 {
			let pubkey = OwnerPubkey::from(Fr::from(i));
			let blinding = Blinding::from(Fr::from(i * 2));
			let commitment = service.create_commitment(i, i, pubkey, blinding);
			commitments.push(commitment);
		}
		// All should be different with sum hasher
		for i in 0..commitments.len() {
			for j in i + 1..commitments.len() {
				assert_ne!(commitments[i], commitments[j]);
			}
		}
	}

	// ===== Reference Tests =====

	#[test]
	fn test_service_reference() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let service_ref = &service;
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment = service_ref.create_commitment(50, 0, pubkey, blinding);
		assert_eq!(commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_commitment_from_service_is_commitment_type() {
		let hasher = MockHasherConstant;
		let service = CommitmentService::new(hasher);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment = service.create_commitment(50, 0, pubkey, blinding);
		// Should be a Commitment type
		let _: Commitment = commitment;
	}

	#[test]
	fn test_different_services_same_inputs() {
		let hasher1 = MockHasherConstant;
		let hasher2 = MockHasherConstant;
		let service1 = CommitmentService::new(hasher1);
		let service2 = CommitmentService::new(hasher2);
		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));
		let commitment1 = service1.create_commitment(50, 0, pubkey, blinding);
		let commitment2 = service2.create_commitment(50, 0, pubkey, blinding);
		assert_eq!(commitment1, commitment2);
	}
}
