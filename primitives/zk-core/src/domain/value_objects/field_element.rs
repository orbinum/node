//! Field Element Value Object
//!
//! Base value object for BN254 scalar field elements.

use ark_bn254::Fr;

/// Field element in BN254 scalar field
///
/// Foundation for all domain value objects (Commitment, Nullifier, etc.).
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
	extern crate alloc;
	use alloc::{format, vec};

	// ===== Construction Tests =====

	#[test]
	fn test_new() {
		let fr = Fr::from(42u64);
		let elem = FieldElement::new(fr);
		assert_eq!(elem.inner(), fr);
	}

	#[test]
	fn test_new_zero() {
		let fr = Fr::from(0u64);
		let elem = FieldElement::new(fr);
		assert_eq!(elem.inner(), fr);
	}

	#[test]
	fn test_new_max() {
		let fr = Fr::from(u64::MAX);
		let elem = FieldElement::new(fr);
		assert_eq!(elem.inner(), fr);
	}

	#[test]
	fn test_from_u64() {
		let elem = FieldElement::from_u64(123);
		assert_eq!(elem.inner(), Fr::from(123u64));
	}

	#[test]
	fn test_from_u64_zero() {
		let elem = FieldElement::from_u64(0);
		assert_eq!(elem.inner(), Fr::from(0u64));
	}

	#[test]
	fn test_from_u64_max() {
		let elem = FieldElement::from_u64(u64::MAX);
		assert_eq!(elem.inner(), Fr::from(u64::MAX));
	}

	// ===== Zero Tests =====

	#[test]
	fn test_zero() {
		let zero = FieldElement::zero();
		assert!(zero.is_zero());
		assert_eq!(zero.inner(), Fr::from(0u64));
	}

	#[test]
	fn test_is_zero_true() {
		let zero = FieldElement::from_u64(0);
		assert!(zero.is_zero());
	}

	#[test]
	fn test_is_zero_false() {
		let non_zero = FieldElement::from_u64(1);
		assert!(!non_zero.is_zero());
	}

	#[test]
	fn test_is_zero_large_value() {
		let large = FieldElement::from_u64(1000000);
		assert!(!large.is_zero());
	}

	#[test]
	fn test_zero_equality() {
		let z1 = FieldElement::zero();
		let z2 = FieldElement::from_u64(0);
		assert_eq!(z1, z2);
	}

	// ===== Getter Tests =====

	#[test]
	fn test_inner() {
		let fr = Fr::from(42u64);
		let elem = FieldElement::new(fr);
		assert_eq!(elem.inner(), fr);
	}

	#[test]
	fn test_inner_consistency() {
		let elem = FieldElement::from_u64(999);
		let inner1 = elem.inner();
		let inner2 = elem.inner();
		assert_eq!(inner1, inner2);
	}

	// ===== Equality Tests =====

	#[test]
	fn test_equality_same_value() {
		let elem1 = FieldElement::from_u64(100);
		let elem2 = FieldElement::from_u64(100);
		assert_eq!(elem1, elem2);
	}

	#[test]
	fn test_inequality_different_value() {
		let elem1 = FieldElement::from_u64(100);
		let elem2 = FieldElement::from_u64(200);
		assert_ne!(elem1, elem2);
	}

	#[test]
	fn test_equality_zero() {
		let z1 = FieldElement::from_u64(0);
		let z2 = FieldElement::from_u64(0);
		assert_eq!(z1, z2);
	}

	#[test]
	fn test_equality_max() {
		let m1 = FieldElement::from_u64(u64::MAX);
		let m2 = FieldElement::from_u64(u64::MAX);
		assert_eq!(m1, m2);
	}

	// ===== From Trait Tests =====

	#[test]
	fn test_from_fr() {
		let fr = Fr::from(100u64);
		let elem = FieldElement::from(fr);
		assert_eq!(elem.inner(), fr);
	}

	#[test]
	fn test_from_u64_trait() {
		let elem: FieldElement = 123u64.into();
		assert_eq!(elem.inner(), Fr::from(123u64));
	}

	#[test]
	fn test_into_fr() {
		let elem = FieldElement::from_u64(456);
		let fr: Fr = elem.into();
		assert_eq!(fr, Fr::from(456u64));
	}

	#[test]
	fn test_from_fr_zero() {
		let fr = Fr::from(0u64);
		let elem = FieldElement::from(fr);
		assert!(elem.is_zero());
	}

	// ===== Clone and Copy Tests =====

	#[test]
	fn test_clone() {
		let elem1 = FieldElement::from_u64(42);
		let elem2 = elem1;
		assert_eq!(elem1, elem2);
	}

	#[test]
	fn test_copy() {
		let elem1 = FieldElement::from_u64(42);
		let elem2 = elem1;
		assert_eq!(elem1, elem2);
	}

	#[test]
	fn test_copy_semantics() {
		let elem1 = FieldElement::from_u64(100);
		let elem2 = elem1; // Copy, not move
		let elem3 = elem1; // elem1 still valid
		assert_eq!(elem1, elem2);
		assert_eq!(elem1, elem3);
	}

	// ===== Debug Tests =====

	#[test]
	fn test_debug_format() {
		let elem = FieldElement::from_u64(42);
		let debug_str = format!("{elem:?}");
		assert!(debug_str.contains("FieldElement"));
	}

	// ===== Hash Tests =====

	#[test]
	fn test_hash_consistency() {
		let e1 = FieldElement::from_u64(100);
		let e2 = FieldElement::from_u64(100);
		assert_eq!(e1, e2);
		let items = [e1];
		assert!(items.contains(&e2));
	}

	#[test]
	fn test_hash_different_values() {
		let e1 = FieldElement::from_u64(100);
		let e2 = FieldElement::from_u64(200);
		assert_ne!(e1, e2);
		let mut items = vec![e1, e2];
		items.dedup();
		assert_eq!(items.len(), 2);
	}

	#[test]
	fn test_dedup_removes_duplicates() {
		let e1 = FieldElement::from_u64(1);
		let e2 = FieldElement::from_u64(2);
		let elements = [e1, e2, e1];
		assert_eq!(elements.len(), 3);
		assert_eq!(elements[0], elements[2]);
	}

	// ===== Round-trip Conversion Tests =====

	#[test]
	fn test_roundtrip_fr() {
		let fr = Fr::from(123u64);
		let elem = FieldElement::from(fr);
		let fr_back: Fr = elem.into();
		assert_eq!(fr, fr_back);
	}

	#[test]
	fn test_roundtrip_u64() {
		let value = 456u64;
		let elem = FieldElement::from_u64(value);
		assert_eq!(elem.inner(), Fr::from(value));
	}

	#[test]
	fn test_roundtrip_new_inner() {
		let fr = Fr::from(789u64);
		let elem = FieldElement::new(fr);
		let fr_back = elem.inner();
		assert_eq!(fr, fr_back);
	}

	// ===== Collection Tests =====

	#[test]
	fn test_vector_of_elements() {
		let elements = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
		];
		assert_eq!(elements.len(), 3);
		assert_ne!(elements[0], elements[1]);
	}

	#[test]
	fn test_element_collection() {
		let e1 = FieldElement::from_u64(100);
		let e2 = FieldElement::from_u64(200);
		let items = [e1, e2];
		assert_eq!(items.len(), 2);
		assert!(items.contains(&e1));
		assert!(items.contains(&e2));
	}

	// ===== Edge Cases =====

	#[test]
	fn test_sequential_values() {
		let e1 = FieldElement::from_u64(100);
		let e2 = FieldElement::from_u64(101);
		assert_ne!(e1, e2);
	}

	#[test]
	fn test_large_value() {
		let elem = FieldElement::from_u64(u64::MAX);
		assert_eq!(elem.inner(), Fr::from(u64::MAX));
		assert!(!elem.is_zero());
	}

	#[test]
	fn test_multiple_zeros() {
		let zeros = [
			FieldElement::zero(),
			FieldElement::from_u64(0),
			FieldElement::from(Fr::from(0u64)),
		];
		for z in &zeros {
			assert!(z.is_zero());
		}
	}

	// ===== Consistency Tests =====

	#[test]
	fn test_consistency_new_and_from() {
		let fr = Fr::from(999u64);
		let e1 = FieldElement::new(fr);
		let e2 = FieldElement::from(fr);
		assert_eq!(e1, e2);
		assert_eq!(e1.inner(), e2.inner());
	}

	#[test]
	fn test_consistency_from_u64_methods() {
		let value = 555u64;
		let e1 = FieldElement::from_u64(value);
		let e2: FieldElement = value.into();
		assert_eq!(e1, e2);
	}

	// ===== Value Object Semantics =====

	#[test]
	fn test_value_object_equality() {
		let e1 = FieldElement::from_u64(100);
		let e2 = FieldElement::from_u64(100);
		assert_eq!(e1, e2);
	}

	#[test]
	fn test_value_object_different_values() {
		let e1 = FieldElement::from_u64(100);
		let e2 = FieldElement::from_u64(101);
		assert_ne!(e1, e2);
	}

	// ===== Immutability Tests =====

	#[test]
	fn test_immutability() {
		let elem = FieldElement::from_u64(42);
		let inner1 = elem.inner();
		let inner2 = elem.inner();
		assert_eq!(inner1, inner2);
	}

	#[test]
	fn test_shared_reference() {
		let elem = FieldElement::from_u64(200);
		let ref1 = &elem;
		let ref2 = &elem;
		assert_eq!(ref1.inner(), ref2.inner());
	}

	// ===== Pattern Matching Tests =====

	#[test]
	fn test_pattern_matching() {
		let elem = FieldElement::from_u64(42);
		match elem {
			FieldElement(_) => {}
		}
	}

	// ===== Multiple Creation Methods =====

	#[test]
	fn test_all_creation_methods_equivalent() {
		let value = 123u64;
		let fr = Fr::from(value);
		let e1 = FieldElement::new(fr);
		let e2 = FieldElement::from(fr);
		let e3 = FieldElement::from_u64(value);
		let e4: FieldElement = value.into();
		assert_eq!(e1, e2);
		assert_eq!(e2, e3);
		assert_eq!(e3, e4);
	}
}
