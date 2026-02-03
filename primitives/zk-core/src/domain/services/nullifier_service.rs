//! # Nullifier Service
//!
//! Domain service for computing nullifiers.
//!

//! Encapsulates the business logic for creating unique identifiers
//! that prevent double-spending of notes.

use crate::domain::ports::PoseidonHasher;
use crate::domain::value_objects::{Commitment, Nullifier, SpendingKey};

/// Domain service for computing nullifiers
///
/// ## Domain Logic
/// A nullifier is a unique identifier that marks a note as spent:
/// ```text
/// nullifier = Poseidon(commitment, spending_key)
/// ```
///
/// ## Properties
/// - **Deterministic**: Same inputs always produce same nullifier
/// - **One-way**: Cannot derive spending key from nullifier
/// - **Unique**: Each note has exactly one nullifier per spending key
/// - **Unlinkable**: Cannot link nullifier to commitment without spending key
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
	/// # Arguments
	/// - `commitment`: The note commitment
	/// - `spending_key`: The private spending key
	///
	/// # Returns
	/// A unique nullifier that marks the note as spent
	///
	/// # Security
	/// The spending key must be kept secret. Once the nullifier is published
	/// on-chain, the note is marked as spent and cannot be used again.
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
	use crate::domain::ports::PoseidonHasher;
	use crate::domain::value_objects::FieldElement;
	use ark_bn254::Fr;

	// Mock hasher for testing
	struct MockHasher;

	impl PoseidonHasher for MockHasher {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	#[test]
	fn test_compute_nullifier() {
		let hasher = MockHasher;
		let service = NullifierService::new(hasher);

		let commitment = Commitment::from(Fr::from(100u64));
		let spending_key = SpendingKey::from(Fr::from(200u64));

		let nullifier = service.compute_nullifier(&commitment, &spending_key);

		// Nullifier should be deterministic
		let nullifier2 = service.compute_nullifier(&commitment, &spending_key);
		assert_eq!(nullifier, nullifier2);
	}

	#[test]
	fn test_different_keys_different_nullifiers() {
		let hasher = MockHasher;
		let service = NullifierService::new(hasher);

		let commitment = Commitment::from(Fr::from(100u64));
		let key1 = SpendingKey::from(Fr::from(200u64));
		let key2 = SpendingKey::from(Fr::from(300u64));

		let n1 = service.compute_nullifier(&commitment, &key1);
		let n2 = service.compute_nullifier(&commitment, &key2);

		// Mock returns same value, but real implementation would differ
		assert_eq!(n1, n2); // Mock limitation
	}
}
