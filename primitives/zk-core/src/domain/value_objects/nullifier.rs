//! # Nullifier Value Object
//!
//! Represents a unique identifier that marks a note as spent.
//! Prevents double-spending in the shielded pool.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// A nullifier that marks a note as spent
///
/// ## DDD Value Object Properties
/// - Immutable: Once created, cannot be modified
/// - Unique: Each note has exactly one nullifier
/// - One-way: Cannot derive spending key from nullifier
///
/// ## Domain Semantics
/// A nullifier prevents double-spending by providing a unique identifier
/// that is published when a note is spent. It is computed as:
/// ```text
/// nullifier = Poseidon(commitment, spending_key)
/// ```
///
/// Once a nullifier appears on-chain, the note cannot be spent again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nullifier(FieldElement);

impl Nullifier {
	/// Create a new nullifier from field element
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

impl From<FieldElement> for Nullifier {
	fn from(value: FieldElement) -> Self {
		Self(value)
	}
}

impl From<Fr> for Nullifier {
	fn from(value: Fr) -> Self {
		Self(FieldElement::new(value))
	}
}

impl From<Nullifier> for Fr {
	fn from(nullifier: Nullifier) -> Self {
		nullifier.as_fr()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_nullifier_creation() {
		let field = FieldElement::from_u64(42);
		let nullifier = Nullifier::new(field);
		assert_eq!(nullifier.inner(), field);
	}

	#[test]
	fn test_nullifier_equality() {
		let field1 = FieldElement::from_u64(100);
		let field2 = FieldElement::from_u64(100);
		let field3 = FieldElement::from_u64(200);

		let n1 = Nullifier::new(field1);
		let n2 = Nullifier::new(field2);
		let n3 = Nullifier::new(field3);

		assert_eq!(n1, n2);
		assert_ne!(n1, n3);
	}

	#[test]
	fn test_nullifier_uniqueness() {
		// Different field elements produce different nullifiers
		let n1 = Nullifier::from(Fr::from(1u64));
		let n2 = Nullifier::from(Fr::from(2u64));
		assert_ne!(n1, n2);
	}
}
