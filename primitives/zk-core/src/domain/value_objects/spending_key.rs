//! Spending Key Value Object
//!
//! Private key required to spend a note. Must be kept secret.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// Private spending key for spending notes
///
/// Used to compute nullifier: `nullifier = Poseidon(commitment, spending_key)`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendingKey(FieldElement);

impl SpendingKey {
	/// Create a new spending key from field element
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

impl From<FieldElement> for SpendingKey {
	fn from(value: FieldElement) -> Self {
		Self(value)
	}
}

impl From<Fr> for SpendingKey {
	fn from(value: Fr) -> Self {
		Self(FieldElement::new(value))
	}
}

impl From<SpendingKey> for Fr {
	fn from(key: SpendingKey) -> Self {
		key.as_fr()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::format;

	// ===== Construction Tests =====

	#[test]
	fn test_new() {
		let field = FieldElement::from_u64(42);
		let key = SpendingKey::new(field);
		assert_eq!(key.inner(), field);
	}

	#[test]
	fn test_new_zero() {
		let field = FieldElement::from_u64(0);
		let key = SpendingKey::new(field);
		assert_eq!(key.inner(), field);
	}

	#[test]
	fn test_new_max() {
		let field = FieldElement::from_u64(u64::MAX);
		let key = SpendingKey::new(field);
		assert_eq!(key.inner(), field);
	}

	#[test]
	fn test_from_u64() {
		let key = SpendingKey::from_u64(123);
		assert_eq!(key.inner(), FieldElement::from_u64(123));
	}

	#[test]
	fn test_from_u64_zero() {
		let key = SpendingKey::from_u64(0);
		assert_eq!(key.inner(), FieldElement::from_u64(0));
	}

	#[test]
	fn test_from_u64_max() {
		let key = SpendingKey::from_u64(u64::MAX);
		assert_eq!(key.inner(), FieldElement::from_u64(u64::MAX));
	}

	// ===== Getter Tests =====

	#[test]
	fn test_inner() {
		let field = FieldElement::from_u64(42);
		let key = SpendingKey::new(field);
		assert_eq!(key.inner(), field);
	}

	#[test]
	fn test_as_fr() {
		let fr = Fr::from(100u64);
		let key = SpendingKey::from(fr);
		assert_eq!(key.as_fr(), fr);
	}

	#[test]
	fn test_inner_consistency() {
		let field = FieldElement::from_u64(999);
		let key = SpendingKey::new(field);
		assert_eq!(key.inner().inner(), field.inner());
	}

	// ===== Equality Tests =====

	#[test]
	fn test_equality_same_value() {
		let key1 = SpendingKey::from_u64(100);
		let key2 = SpendingKey::from_u64(100);
		assert_eq!(key1, key2);
	}

	#[test]
	fn test_inequality_different_value() {
		let key1 = SpendingKey::from_u64(100);
		let key2 = SpendingKey::from_u64(200);
		assert_ne!(key1, key2);
	}

	#[test]
	fn test_equality_zero() {
		let key1 = SpendingKey::from_u64(0);
		let key2 = SpendingKey::from_u64(0);
		assert_eq!(key1, key2);
	}

	#[test]
	fn test_equality_max() {
		let key1 = SpendingKey::from_u64(u64::MAX);
		let key2 = SpendingKey::from_u64(u64::MAX);
		assert_eq!(key1, key2);
	}

	// ===== From Trait Tests =====

	#[test]
	fn test_from_field_element() {
		let field = FieldElement::from_u64(42);
		let key = SpendingKey::from(field);
		assert_eq!(key.inner(), field);
	}

	#[test]
	fn test_from_fr() {
		let fr = Fr::from(100u64);
		let key = SpendingKey::from(fr);
		assert_eq!(key.as_fr(), fr);
	}

	#[test]
	fn test_from_fr_zero() {
		let fr = Fr::from(0u64);
		let key = SpendingKey::from(fr);
		assert_eq!(key.as_fr(), fr);
	}

	#[test]
	fn test_into_fr() {
		let key = SpendingKey::from_u64(123);
		let fr: Fr = key.into();
		assert_eq!(fr, Fr::from(123u64));
	}

	#[test]
	fn test_into_fr_zero() {
		let key = SpendingKey::from_u64(0);
		let fr: Fr = key.into();
		assert_eq!(fr, Fr::from(0u64));
	}

	// ===== Clone and Copy Tests =====

	#[test]
	fn test_clone() {
		let key1 = SpendingKey::from_u64(42);
		let key2 = key1;
		assert_eq!(key1, key2);
	}

	#[test]
	fn test_copy() {
		let key1 = SpendingKey::from_u64(42);
		let key2 = key1;
		assert_eq!(key1, key2);
	}

	#[test]
	fn test_copy_semantics() {
		let key1 = SpendingKey::from_u64(100);
		let key2 = key1; // Copy, not move
		let key3 = key1; // key1 still valid
		assert_eq!(key1, key2);
		assert_eq!(key1, key3);
	}

	// ===== Immutability Tests =====

	#[test]
	fn test_immutability() {
		let key = SpendingKey::from(Fr::from(42u64));
		let inner1 = key.inner();
		let inner2 = key.inner();
		assert_eq!(inner1, inner2);
	}

	#[test]
	fn test_shared_reference() {
		let key = SpendingKey::from_u64(200);
		let ref1 = &key;
		let ref2 = &key;
		assert_eq!(ref1.inner(), ref2.inner());
	}

	// ===== Debug Tests =====

	#[test]
	fn test_debug_format() {
		let key = SpendingKey::from_u64(42);
		let debug_str = format!("{key:?}");
		assert!(debug_str.contains("SpendingKey"));
	}

	// ===== Round-trip Conversion Tests =====

	#[test]
	fn test_roundtrip_field_element() {
		let field = FieldElement::from_u64(123);
		let key = SpendingKey::from(field);
		let field_back = key.inner();
		assert_eq!(field, field_back);
	}

	#[test]
	fn test_roundtrip_fr() {
		let fr = Fr::from(456u64);
		let key = SpendingKey::from(fr);
		let fr_back: Fr = key.into();
		assert_eq!(fr, fr_back);
	}

	#[test]
	fn test_roundtrip_new_inner() {
		let field = FieldElement::from_u64(789);
		let key = SpendingKey::new(field);
		let field_back = key.inner();
		assert_eq!(field, field_back);
	}

	// ===== Collection Tests =====

	#[test]
	fn test_vector_of_keys() {
		let keys = [
			SpendingKey::from_u64(1),
			SpendingKey::from_u64(2),
			SpendingKey::from_u64(3),
		];
		assert_eq!(keys.len(), 3);
		assert_ne!(keys[0], keys[1]);
	}

	// ===== Edge Cases =====

	#[test]
	fn test_sequential_values() {
		let key1 = SpendingKey::from_u64(100);
		let key2 = SpendingKey::from_u64(101);
		assert_ne!(key1, key2);
	}

	#[test]
	fn test_large_value() {
		let key = SpendingKey::from_u64(1_000_000_000);
		assert_eq!(key.inner(), FieldElement::from_u64(1_000_000_000));
	}

	#[test]
	fn test_new_equals_from() {
		let field = FieldElement::from_u64(42);
		let key1 = SpendingKey::new(field);
		let key2 = SpendingKey::from(field);
		assert_eq!(key1, key2);
	}

	// ===== Consistency Tests =====

	#[test]
	fn test_consistency_new_and_from() {
		let field = FieldElement::from_u64(999);
		let key1 = SpendingKey::new(field);
		let key2 = SpendingKey::from(field);
		assert_eq!(key1, key2);
		assert_eq!(key1.inner(), key2.inner());
	}

	#[test]
	fn test_consistency_fr_conversions() {
		let fr = Fr::from(555u64);
		let key = SpendingKey::from(fr);
		assert_eq!(key.as_fr(), fr);
		let fr_back: Fr = key.into();
		assert_eq!(fr, fr_back);
	}

	// ===== Value Object Semantics =====

	#[test]
	fn test_value_object_equality() {
		let key1 = SpendingKey::from(Fr::from(100u64));
		let key2 = SpendingKey::from(Fr::from(100u64));
		assert_eq!(key1, key2);
	}

	#[test]
	fn test_value_object_different_values() {
		let key1 = SpendingKey::from(Fr::from(100u64));
		let key2 = SpendingKey::from(Fr::from(101u64));
		assert_ne!(key1, key2);
	}

	// ===== Pattern Matching Tests =====

	#[test]
	fn test_pattern_matching() {
		let key = SpendingKey::from_u64(42);
		match key {
			SpendingKey(_) => {}
		}
	}

	// ===== Uniqueness Tests =====

	#[test]
	fn test_different_keys_are_unique() {
		let key1 = SpendingKey::from(Fr::from(1u64));
		let key2 = SpendingKey::from(Fr::from(2u64));
		assert_ne!(key1, key2);
	}
}
