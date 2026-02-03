//! # Commitment Value Object
//!
//! Represents a cryptographic commitment to a note.
//! Commitments are stored in the Merkle tree and hide note details.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// A cryptographic commitment to a note
///
/// ## DDD Value Object Properties
/// - Immutable: Once created, cannot be modified
/// - Equality by value: Two commitments are equal if their values are equal
/// - Self-validating: Maintains its own invariants
///
/// ## Domain Semantics
/// A commitment hides note details (value, asset, owner) while allowing
/// later verification. It is computed as:
/// ```text
/// commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Commitment(FieldElement);

impl Commitment {
	/// Create a new commitment from field element
	pub fn new(value: FieldElement) -> Self {
		Self(value)
	}

	/// Get the inner field element
	pub fn inner(&self) -> FieldElement {
		self.0
	}

	/// Get the raw Fr value
	pub fn as_fr(&self) -> Fr {
		self.0.inner()
	}
}

impl From<FieldElement> for Commitment {
	fn from(value: FieldElement) -> Self {
		Self(value)
	}
}

impl From<Fr> for Commitment {
	fn from(value: Fr) -> Self {
		Self(FieldElement::new(value))
	}
}

impl From<Commitment> for Fr {
	fn from(commitment: Commitment) -> Self {
		commitment.as_fr()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_commitment_creation() {
		let field = FieldElement::from_u64(42);
		let commitment = Commitment::new(field);
		assert_eq!(commitment.inner(), field);
	}

	#[test]
	fn test_commitment_equality() {
		let field1 = FieldElement::from_u64(100);
		let field2 = FieldElement::from_u64(100);
		let field3 = FieldElement::from_u64(200);

		let c1 = Commitment::new(field1);
		let c2 = Commitment::new(field2);
		let c3 = Commitment::new(field3);

		assert_eq!(c1, c2);
		assert_ne!(c1, c3);
	}

	#[test]
	fn test_commitment_immutability() {
		let commitment = Commitment::from(Fr::from(42u64));
		let inner = commitment.inner();

		// Commitment cannot be modified, only cloned
		let commitment2 = commitment;
		assert_eq!(commitment, commitment2);
		assert_eq!(commitment.inner(), inner);
	}
}
