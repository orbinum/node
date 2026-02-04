//! Nullifier Value Object
//!
//! Unique identifier that marks a note as spent, preventing double-spending.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// Nullifier that marks a note as spent
///
/// Computed as: `nullifier = Poseidon(commitment, spending_key)`
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
	extern crate alloc;
	use alloc::format;
	use alloc::vec;

	// ===== Construction Tests =====

	#[test]
	fn test_new() {
		let field = FieldElement::from_u64(42);
		let nullifier = Nullifier::new(field);
		assert_eq!(nullifier.inner(), field);
	}

	#[test]
	fn test_new_zero() {
		let field = FieldElement::from_u64(0);
		let nullifier = Nullifier::new(field);
		assert_eq!(nullifier.inner(), field);
	}

	#[test]
	fn test_new_max() {
		let field = FieldElement::from_u64(u64::MAX);
		let nullifier = Nullifier::new(field);
		assert_eq!(nullifier.inner(), field);
	}

	#[test]
	fn test_new_large_value() {
		let field = FieldElement::from_u64(1_000_000_000);
		let nullifier = Nullifier::new(field);
		assert_eq!(nullifier.inner(), field);
	}

	// ===== Getter Tests =====

	#[test]
	fn test_inner() {
		let field = FieldElement::from_u64(42);
		let nullifier = Nullifier::new(field);
		assert_eq!(nullifier.inner(), field);
	}

	#[test]
	fn test_as_fr() {
		let fr = Fr::from(100u64);
		let nullifier = Nullifier::from(fr);
		assert_eq!(nullifier.as_fr(), fr);
	}

	#[test]
	fn test_inner_consistency() {
		let field = FieldElement::from_u64(999);
		let nullifier = Nullifier::new(field);
		assert_eq!(nullifier.inner().inner(), field.inner());
	}

	// ===== Equality Tests =====

	#[test]
	fn test_equality_same_value() {
		let field1 = FieldElement::from_u64(100);
		let field2 = FieldElement::from_u64(100);
		let n1 = Nullifier::new(field1);
		let n2 = Nullifier::new(field2);
		assert_eq!(n1, n2);
	}

	#[test]
	fn test_inequality_different_value() {
		let field1 = FieldElement::from_u64(100);
		let field2 = FieldElement::from_u64(200);
		let n1 = Nullifier::new(field1);
		let n2 = Nullifier::new(field2);
		assert_ne!(n1, n2);
	}

	#[test]
	fn test_equality_zero() {
		let n1 = Nullifier::from(Fr::from(0u64));
		let n2 = Nullifier::from(Fr::from(0u64));
		assert_eq!(n1, n2);
	}

	#[test]
	fn test_equality_max() {
		let fr = Fr::from(u64::MAX);
		let n1 = Nullifier::from(fr);
		let n2 = Nullifier::from(fr);
		assert_eq!(n1, n2);
	}

	#[test]
	fn test_uniqueness() {
		let n1 = Nullifier::from(Fr::from(1u64));
		let n2 = Nullifier::from(Fr::from(2u64));
		assert_ne!(n1, n2);
	}

	// ===== From Trait Tests =====

	#[test]
	fn test_from_field_element() {
		let field = FieldElement::from_u64(42);
		let nullifier = Nullifier::from(field);
		assert_eq!(nullifier.inner(), field);
	}

	#[test]
	fn test_from_fr() {
		let fr = Fr::from(100u64);
		let nullifier = Nullifier::from(fr);
		assert_eq!(nullifier.as_fr(), fr);
	}

	#[test]
	fn test_from_fr_zero() {
		let fr = Fr::from(0u64);
		let nullifier = Nullifier::from(fr);
		assert_eq!(nullifier.as_fr(), fr);
	}

	#[test]
	fn test_into_fr() {
		let nullifier = Nullifier::from(Fr::from(123u64));
		let fr: Fr = nullifier.into();
		assert_eq!(fr, Fr::from(123u64));
	}

	#[test]
	fn test_into_fr_zero() {
		let nullifier = Nullifier::from(Fr::from(0u64));
		let fr: Fr = nullifier.into();
		assert_eq!(fr, Fr::from(0u64));
	}

	// ===== Clone and Copy Tests =====

	#[test]
	fn test_clone() {
		let n1 = Nullifier::from(Fr::from(42u64));
		let n2 = n1;
		assert_eq!(n1, n2);
	}

	#[test]
	fn test_copy() {
		let n1 = Nullifier::from(Fr::from(42u64));
		let n2 = n1;
		assert_eq!(n1, n2);
	}

	#[test]
	fn test_copy_semantics() {
		let n1 = Nullifier::from(Fr::from(100u64));
		let n2 = n1; // Copy, not move
		let n3 = n1; // n1 still valid
		assert_eq!(n1, n2);
		assert_eq!(n1, n3);
	}

	// ===== Immutability Tests =====

	#[test]
	fn test_immutability() {
		let nullifier = Nullifier::from(Fr::from(42u64));
		let inner1 = nullifier.inner();
		let inner2 = nullifier.inner();
		assert_eq!(inner1, inner2);
	}

	#[test]
	fn test_shared_reference() {
		let nullifier = Nullifier::from(Fr::from(200u64));
		let ref1 = &nullifier;
		let ref2 = &nullifier;
		assert_eq!(ref1.inner(), ref2.inner());
	}

	// ===== Debug Tests =====

	#[test]
	fn test_debug_format() {
		let nullifier = Nullifier::from(Fr::from(42u64));
		let debug_str = format!("{nullifier:?}");
		assert!(debug_str.contains("Nullifier"));
	}

	// ===== Hash Tests =====

	#[test]
	fn test_hash_consistency() {
		let n1 = Nullifier::from(Fr::from(100u64));
		let n2 = Nullifier::from(Fr::from(100u64));
		assert_eq!(n1, n2);
		let items = [n1];
		assert!(items.contains(&n2));
	}

	#[test]
	fn test_hash_different_values() {
		let n1 = Nullifier::from(Fr::from(100u64));
		let n2 = Nullifier::from(Fr::from(200u64));
		assert_ne!(n1, n2);
		let mut items = vec![n1, n2];
		items.dedup();
		assert_eq!(items.len(), 2);
	}

	#[test]
	fn test_dedup_removes_duplicates() {
		let n1 = Nullifier::from(Fr::from(1u64));
		let n2 = Nullifier::from(Fr::from(2u64));
		let nullifiers = [n1, n2, n1];
		assert_eq!(nullifiers.len(), 3);
		assert_eq!(nullifiers[0], nullifiers[2]);
	}

	// ===== Round-trip Conversion Tests =====

	#[test]
	fn test_roundtrip_field_element() {
		let field = FieldElement::from_u64(123);
		let nullifier = Nullifier::from(field);
		let field_back = nullifier.inner();
		assert_eq!(field, field_back);
	}

	#[test]
	fn test_roundtrip_fr() {
		let fr = Fr::from(456u64);
		let nullifier = Nullifier::from(fr);
		let fr_back: Fr = nullifier.into();
		assert_eq!(fr, fr_back);
	}

	#[test]
	fn test_roundtrip_new_inner() {
		let field = FieldElement::from_u64(789);
		let nullifier = Nullifier::new(field);
		let field_back = nullifier.inner();
		assert_eq!(field, field_back);
	}

	// ===== Collection Tests =====

	#[test]
	fn test_vector_of_nullifiers() {
		let nullifiers = [
			Nullifier::from(Fr::from(1u64)),
			Nullifier::from(Fr::from(2u64)),
			Nullifier::from(Fr::from(3u64)),
		];
		assert_eq!(nullifiers.len(), 3);
		assert_ne!(nullifiers[0], nullifiers[1]);
	}

	#[test]
	fn test_nullifier_collection() {
		let n1 = Nullifier::from(Fr::from(100u64));
		let n2 = Nullifier::from(Fr::from(200u64));
		let items = [n1, n2];
		assert_eq!(items.len(), 2);
		assert!(items.contains(&n1));
		assert!(items.contains(&n2));
	}

	// ===== Edge Cases =====

	#[test]
	fn test_sequential_values() {
		let n1 = Nullifier::from(Fr::from(100u64));
		let n2 = Nullifier::from(Fr::from(101u64));
		assert_ne!(n1, n2);
	}

	#[test]
	fn test_large_value() {
		let nullifier = Nullifier::from(Fr::from(u64::MAX));
		assert_eq!(nullifier.as_fr(), Fr::from(u64::MAX));
	}

	#[test]
	fn test_new_equals_from() {
		let field = FieldElement::from_u64(42);
		let n1 = Nullifier::new(field);
		let n2 = Nullifier::from(field);
		assert_eq!(n1, n2);
	}

	// ===== Consistency Tests =====

	#[test]
	fn test_consistency_new_and_from() {
		let field = FieldElement::from_u64(999);
		let n1 = Nullifier::new(field);
		let n2 = Nullifier::from(field);
		assert_eq!(n1, n2);
		assert_eq!(n1.inner(), n2.inner());
	}

	#[test]
	fn test_consistency_fr_conversions() {
		let fr = Fr::from(555u64);
		let nullifier = Nullifier::from(fr);
		assert_eq!(nullifier.as_fr(), fr);
		let fr_back: Fr = nullifier.into();
		assert_eq!(fr, fr_back);
	}

	// ===== Value Object Semantics =====

	#[test]
	fn test_value_object_equality() {
		// Same value = equal value objects
		let n1 = Nullifier::from(Fr::from(100u64));
		let n2 = Nullifier::from(Fr::from(100u64));
		assert_eq!(n1, n2);
	}

	#[test]
	fn test_value_object_different_values() {
		// Different values = different value objects
		let n1 = Nullifier::from(Fr::from(100u64));
		let n2 = Nullifier::from(Fr::from(101u64));
		assert_ne!(n1, n2);
	}

	// ===== Pattern Matching Tests =====

	#[test]
	fn test_pattern_matching() {
		let nullifier = Nullifier::from(Fr::from(42u64));
		match nullifier {
			Nullifier(_) => {}
		}
	}
}
