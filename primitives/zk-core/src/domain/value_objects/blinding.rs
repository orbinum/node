//! # Blinding Factor Value Object
//!
//! Represents a random blinding factor used to hide note commitments.
//! Ensures unlinkability between notes.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// A random blinding factor for hiding note commitments
///
/// ## DDD Value Object Properties
/// - Immutable: Once created, cannot be modified
/// - Random: Should be generated from secure randomness
/// - Unique: Each note should have a unique blinding factor
///
/// ## Domain Semantics
/// The blinding factor provides unlinkability. Two notes with the same
/// value, asset, and owner will have different commitments if they use
/// different blinding factors:
/// ```text
/// commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
/// ```
///
/// ## Security
/// - Must be generated from cryptographically secure random source
/// - Should never be reused across different notes
/// - Must be stored with the note for later spending
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blinding(FieldElement);

impl Blinding {
	/// Create a new blinding factor from field element
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

	/// Generate from u64 (for testing only, not cryptographically secure)
	#[cfg(test)]
	pub fn from_u64(value: u64) -> Self {
		Self(FieldElement::from_u64(value))
	}
}

impl From<FieldElement> for Blinding {
	fn from(value: FieldElement) -> Self {
		Self(value)
	}
}

impl From<Fr> for Blinding {
	fn from(value: Fr) -> Self {
		Self(FieldElement::new(value))
	}
}

impl From<Blinding> for Fr {
	fn from(blinding: Blinding) -> Self {
		blinding.as_fr()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_blinding_creation() {
		let field = FieldElement::from_u64(42);
		let blinding = Blinding::new(field);
		assert_eq!(blinding.inner(), field);
	}

	#[test]
	fn test_blinding_equality() {
		let b1 = Blinding::from_u64(100);
		let b2 = Blinding::from_u64(100);
		let b3 = Blinding::from_u64(200);

		assert_eq!(b1, b2);
		assert_ne!(b1, b3);
	}

	#[test]
	fn test_blinding_uniqueness() {
		// Different blinding factors should be different
		let b1 = Blinding::from(Fr::from(1u64));
		let b2 = Blinding::from(Fr::from(2u64));
		assert_ne!(b1, b2);
	}
}
