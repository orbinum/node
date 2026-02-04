//! Blinding Factor Value Object
//!
//! Random blinding factor used to hide note commitments and ensure unlinkability.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// Random blinding factor for hiding note commitments
///
/// Provides unlinkability: `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
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

	/// Generate from u64 (for testing only)
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
	extern crate alloc;
	use alloc::format;

	use alloc::vec::Vec;

	// ===== Construction Tests =====

	#[test]
	fn test_new() {
		let field = FieldElement::from_u64(42);
		let blinding = Blinding::new(field);
		assert_eq!(blinding.inner(), field);
	}

	#[test]
	fn test_new_zero() {
		let field = FieldElement::from_u64(0);
		let blinding = Blinding::new(field);
		assert_eq!(blinding.inner(), field);
	}

	#[test]
	fn test_new_max() {
		let field = FieldElement::from_u64(u64::MAX);
		let blinding = Blinding::new(field);
		assert_eq!(blinding.inner(), field);
	}

	#[test]
	fn test_from_u64() {
		let blinding = Blinding::from_u64(123);
		assert_eq!(blinding.inner(), FieldElement::from_u64(123));
	}

	#[test]
	fn test_from_u64_zero() {
		let blinding = Blinding::from_u64(0);
		assert_eq!(blinding.inner(), FieldElement::from_u64(0));
	}

	#[test]
	fn test_from_u64_max() {
		let blinding = Blinding::from_u64(u64::MAX);
		assert_eq!(blinding.inner(), FieldElement::from_u64(u64::MAX));
	}

	// ===== Getter Tests =====

	#[test]
	fn test_inner() {
		let field = FieldElement::from_u64(42);
		let blinding = Blinding::new(field);
		assert_eq!(blinding.inner(), field);
	}

	#[test]
	fn test_as_fr() {
		let fr = Fr::from(100u64);
		let blinding = Blinding::from(fr);
		assert_eq!(blinding.as_fr(), fr);
	}

	#[test]
	fn test_inner_consistency() {
		let field = FieldElement::from_u64(999);
		let blinding = Blinding::new(field);
		assert_eq!(blinding.inner().inner(), field.inner());
	}

	// ===== Equality Tests =====

	#[test]
	fn test_equality_same_value() {
		let b1 = Blinding::from_u64(100);
		let b2 = Blinding::from_u64(100);
		assert_eq!(b1, b2);
	}

	#[test]
	fn test_inequality_different_value() {
		let b1 = Blinding::from_u64(100);
		let b2 = Blinding::from_u64(200);
		assert_ne!(b1, b2);
	}

	#[test]
	fn test_equality_zero() {
		let b1 = Blinding::from_u64(0);
		let b2 = Blinding::from_u64(0);
		assert_eq!(b1, b2);
	}

	#[test]
	fn test_equality_max() {
		let b1 = Blinding::from_u64(u64::MAX);
		let b2 = Blinding::from_u64(u64::MAX);
		assert_eq!(b1, b2);
	}

	#[test]
	fn test_uniqueness() {
		let b1 = Blinding::from(Fr::from(1u64));
		let b2 = Blinding::from(Fr::from(2u64));
		assert_ne!(b1, b2);
	}

	// ===== From Trait Tests =====

	#[test]
	fn test_from_field_element() {
		let field = FieldElement::from_u64(42);
		let blinding = Blinding::from(field);
		assert_eq!(blinding.inner(), field);
	}

	#[test]
	fn test_from_fr() {
		let fr = Fr::from(100u64);
		let blinding = Blinding::from(fr);
		assert_eq!(blinding.as_fr(), fr);
	}

	#[test]
	fn test_from_fr_zero() {
		let fr = Fr::from(0u64);
		let blinding = Blinding::from(fr);
		assert_eq!(blinding.as_fr(), fr);
	}

	#[test]
	fn test_into_fr() {
		let blinding = Blinding::from_u64(123);
		let fr: Fr = blinding.into();
		assert_eq!(fr, Fr::from(123u64));
	}

	#[test]
	fn test_into_fr_zero() {
		let blinding = Blinding::from_u64(0);
		let fr: Fr = blinding.into();
		assert_eq!(fr, Fr::from(0u64));
	}

	// ===== Clone and Copy Tests =====

	#[test]
	fn test_clone() {
		let b1 = Blinding::from_u64(42);
		let b2 = b1;
		assert_eq!(b1, b2);
	}

	#[test]
	fn test_copy() {
		let b1 = Blinding::from_u64(42);
		let b2 = b1;
		assert_eq!(b1, b2);
	}

	#[test]
	fn test_copy_semantics() {
		let b1 = Blinding::from_u64(100);
		let b2 = b1; // Copy, not move
		let b3 = b1; // b1 still valid
		assert_eq!(b1, b2);
		assert_eq!(b1, b3);
	}

	// ===== Debug Tests =====

	#[test]
	fn test_debug_format() {
		let blinding = Blinding::from_u64(42);
		let debug_str = format!("{blinding:?}");
		assert!(debug_str.contains("Blinding"));
	}

	// ===== Round-trip Conversion Tests =====

	#[test]
	fn test_roundtrip_field_element() {
		let field = FieldElement::from_u64(123);
		let blinding = Blinding::from(field);
		let field_back = blinding.inner();
		assert_eq!(field, field_back);
	}

	#[test]
	fn test_roundtrip_fr() {
		let fr = Fr::from(456u64);
		let blinding = Blinding::from(fr);
		let fr_back: Fr = blinding.into();
		assert_eq!(fr, fr_back);
	}

	#[test]
	fn test_roundtrip_new_inner() {
		let field = FieldElement::from_u64(789);
		let blinding = Blinding::new(field);
		let field_back = blinding.inner();
		assert_eq!(field, field_back);
	}

	// ===== Multiple Blinding Factors Tests =====

	#[test]
	fn test_multiple_different_blindings() {
		let blindings: Vec<_> = (0..10).map(Blinding::from_u64).collect();
		for i in 0..blindings.len() - 1 {
			for j in i + 1..blindings.len() {
				assert_ne!(blindings[i], blindings[j]);
			}
		}
	}

	#[test]
	fn test_collection_of_blindings() {
		let blindings = [
			Blinding::from_u64(1),
			Blinding::from_u64(2),
			Blinding::from_u64(3),
		];
		assert_eq!(blindings.len(), 3);
		assert_ne!(blindings[0], blindings[1]);
		assert_ne!(blindings[1], blindings[2]);
	}

	// ===== Edge Cases =====

	#[test]
	fn test_sequential_values() {
		let b1 = Blinding::from_u64(100);
		let b2 = Blinding::from_u64(101);
		assert_ne!(b1, b2);
	}

	#[test]
	fn test_large_value() {
		let blinding = Blinding::from_u64(1_000_000_000);
		assert_eq!(blinding.inner(), FieldElement::from_u64(1_000_000_000));
	}

	#[test]
	fn test_new_equals_from() {
		let field = FieldElement::from_u64(42);
		let b1 = Blinding::new(field);
		let b2 = Blinding::from(field);
		assert_eq!(b1, b2);
	}

	// ===== Consistency Tests =====

	#[test]
	fn test_consistency_new_and_from_field() {
		let field = FieldElement::from_u64(999);
		let b1 = Blinding::new(field);
		let b2 = Blinding::from(field);
		assert_eq!(b1, b2);
		assert_eq!(b1.inner(), b2.inner());
	}

	#[test]
	fn test_consistency_fr_conversions() {
		let fr = Fr::from(555u64);
		let blinding = Blinding::from(fr);
		assert_eq!(blinding.as_fr(), fr);
		let fr_back: Fr = blinding.into();
		assert_eq!(fr, fr_back);
	}

	// ===== Pattern Matching Tests =====

	#[test]
	fn test_pattern_matching() {
		let blinding = Blinding::from_u64(42);
		match blinding {
			Blinding(_) => {}
		}
	}

	// ===== Immutability Tests =====

	#[test]
	fn test_immutability() {
		let blinding = Blinding::from_u64(100);
		let inner1 = blinding.inner();
		let inner2 = blinding.inner();
		assert_eq!(inner1, inner2);
	}

	#[test]
	fn test_shared_reference() {
		let blinding = Blinding::from_u64(200);
		let ref1 = &blinding;
		let ref2 = &blinding;
		assert_eq!(ref1.inner(), ref2.inner());
	}

	// ===== Value Object Semantics =====

	#[test]
	fn test_value_object_equality() {
		// Same value = equal value objects
		let b1 = Blinding::from(Fr::from(100u64));
		let b2 = Blinding::from(Fr::from(100u64));
		assert_eq!(b1, b2);
	}

	#[test]
	fn test_value_object_different_values() {
		// Different values = different value objects
		let b1 = Blinding::from(Fr::from(100u64));
		let b2 = Blinding::from(Fr::from(101u64));
		assert_ne!(b1, b2);
	}
}
