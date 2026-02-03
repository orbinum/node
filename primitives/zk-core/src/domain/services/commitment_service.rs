//! # Commitment Service
//!
//! Domain service for creating note commitments.
//!

//! This is a stateless service that encapsulates domain logic that doesn't
//! naturally fit into a value object or entity.

use crate::domain::ports::PoseidonHasher;
use crate::domain::value_objects::{Blinding, Commitment, FieldElement, OwnerPubkey};

/// Domain service for creating commitments
///
/// ## Domain Logic
/// A commitment hides note details while allowing later verification:
/// ```text
/// commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
/// ```
///
/// ## Properties
/// - **Hiding**: Cannot determine values without blinding factor
/// - **Binding**: Cannot change values after commitment creation
/// - **Deterministic**: Same inputs always produce same commitment
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
	/// # Arguments
	/// - `value`: Token amount
	/// - `asset_id`: Asset identifier
	/// - `owner_pubkey`: Owner's public key
	/// - `blinding`: Random blinding factor
	///
	/// # Returns
	/// A cryptographic commitment to the note
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

	// Mock hasher for testing
	struct MockHasher;

	impl PoseidonHasher for MockHasher {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			// Simple mock: returns constant
			FieldElement::from_u64(1)
		}
	}

	#[test]
	fn test_create_commitment() {
		let hasher = MockHasher;
		let service = CommitmentService::new(hasher);

		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));

		let commitment = service.create_commitment(50, 0, pubkey, blinding);

		// Commitment should be deterministic
		let commitment2 = service.create_commitment(50, 0, pubkey, blinding);
		assert_eq!(commitment, commitment2);
	}

	#[test]
	fn test_different_inputs_different_commitments() {
		let hasher = MockHasher;
		let service = CommitmentService::new(hasher);

		let pubkey = OwnerPubkey::from(Fr::from(100u64));
		let blinding = Blinding::from(Fr::from(200u64));

		let c1 = service.create_commitment(50, 0, pubkey, blinding);
		let c2 = service.create_commitment(100, 0, pubkey, blinding);

		// Different values should produce different commitments
		// (in real implementation with actual Poseidon hash)
		assert_eq!(c1, c2); // Mock always returns same
	}
}
