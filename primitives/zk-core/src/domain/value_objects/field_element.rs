//! # Field Element Value Object
//!
//! Base value object for BN254 scalar field elements.
//! Wraps arkworks Fr type with domain semantics.

use ark_bn254::Fr;

/// Field element in BN254 scalar field
///
/// This is the foundational value object. All other domain value objects
/// wrap this type with specific semantics (Commitment, Nullifier, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FieldElement(Fr);

impl FieldElement {
	/// Create a new field element
	pub fn new(value: Fr) -> Self {
		Self(value)
	}

	/// Get the inner field element
	pub fn inner(&self) -> Fr {
		self.0
	}

	/// Create from u64 value
	pub fn from_u64(value: u64) -> Self {
		Self(Fr::from(value))
	}

	/// Create zero element
	pub fn zero() -> Self {
		Self(Fr::from(0u64))
	}

	/// Check if element is zero
	pub fn is_zero(&self) -> bool {
		self.0 == Fr::from(0u64)
	}
}

impl From<Fr> for FieldElement {
	fn from(value: Fr) -> Self {
		Self(value)
	}
}

impl From<FieldElement> for Fr {
	fn from(element: FieldElement) -> Self {
		element.0
	}
}

impl From<u64> for FieldElement {
	fn from(value: u64) -> Self {
		Self::from_u64(value)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_field_element_creation() {
		let elem = FieldElement::from_u64(42);
		assert_eq!(elem.inner(), Fr::from(42u64));
	}

	#[test]
	fn test_field_element_zero() {
		let zero = FieldElement::zero();
		assert!(zero.is_zero());
	}

	#[test]
	fn test_field_element_equality() {
		let elem1 = FieldElement::from_u64(100);
		let elem2 = FieldElement::from_u64(100);
		let elem3 = FieldElement::from_u64(200);

		assert_eq!(elem1, elem2);
		assert_ne!(elem1, elem3);
	}
}
