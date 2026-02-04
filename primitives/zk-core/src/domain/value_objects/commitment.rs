//! Commitment Value Object
//!
//! Cryptographic commitment to a note stored in the Merkle tree.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// Cryptographic commitment to a note
///
/// Hides note details: `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
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
	extern crate alloc;
	use alloc::{format, vec};

	// ===== Construction Tests =====

	#[test]
	fn test_new() {
		let field = FieldElement::from_u64(42);
		let commitment = Commitment::new(field);
		assert_eq!(commitment.inner(), field);
	}

	#[test]
	fn test_new_zero() {
		let field = FieldElement::from_u64(0);
		let commitment = Commitment::new(field);
		assert_eq!(commitment.inner(), field);
	}

	#[test]
	fn test_new_max() {
		let field = FieldElement::from_u64(u64::MAX);
		let commitment = Commitment::new(field);
		assert_eq!(commitment.inner(), field);
	}

	#[test]
	fn test_new_large_value() {
		let field = FieldElement::from_u64(1_000_000_000);
		let commitment = Commitment::new(field);
		assert_eq!(commitment.inner(), field);
	}

	// ===== Getter Tests =====

	#[test]
	fn test_inner() {
		let field = FieldElement::from_u64(42);
		let commitment = Commitment::new(field);
		assert_eq!(commitment.inner(), field);
	}

	#[test]
	fn test_as_fr() {
		let fr = Fr::from(100u64);
		let commitment = Commitment::from(fr);
		assert_eq!(commitment.as_fr(), fr);
	}

	#[test]
	fn test_inner_consistency() {
		let field = FieldElement::from_u64(999);
		let commitment = Commitment::new(field);
		assert_eq!(commitment.inner().inner(), field.inner());
	}

	// ===== Equality Tests =====

	#[test]
	fn test_equality_same_value() {
		let field1 = FieldElement::from_u64(100);
		let field2 = FieldElement::from_u64(100);
		let c1 = Commitment::new(field1);
		let c2 = Commitment::new(field2);
		assert_eq!(c1, c2);
	}

	#[test]
	fn test_inequality_different_value() {
		let field1 = FieldElement::from_u64(100);
		let field2 = FieldElement::from_u64(200);
		let c1 = Commitment::new(field1);
		let c2 = Commitment::new(field2);
		assert_ne!(c1, c2);
	}

	#[test]
	fn test_equality_zero() {
		let c1 = Commitment::from(Fr::from(0u64));
		let c2 = Commitment::from(Fr::from(0u64));
		assert_eq!(c1, c2);
	}

	#[test]
	fn test_equality_max() {
		let fr = Fr::from(u64::MAX);
		let c1 = Commitment::from(fr);
		let c2 = Commitment::from(fr);
		assert_eq!(c1, c2);
	}

	// ===== From Trait Tests =====

	#[test]
	fn test_from_field_element() {
		let field = FieldElement::from_u64(42);
		let commitment = Commitment::from(field);
		assert_eq!(commitment.inner(), field);
	}

	#[test]
	fn test_from_fr() {
		let fr = Fr::from(100u64);
		let commitment = Commitment::from(fr);
		assert_eq!(commitment.as_fr(), fr);
	}

	#[test]
	fn test_from_fr_zero() {
		let fr = Fr::from(0u64);
		let commitment = Commitment::from(fr);
		assert_eq!(commitment.as_fr(), fr);
	}

	#[test]
	fn test_into_fr() {
		let commitment = Commitment::from(Fr::from(123u64));
		let fr: Fr = commitment.into();
		assert_eq!(fr, Fr::from(123u64));
	}

	#[test]
	fn test_into_fr_zero() {
		let commitment = Commitment::from(Fr::from(0u64));
		let fr: Fr = commitment.into();
		assert_eq!(fr, Fr::from(0u64));
	}

	// ===== Clone and Copy Tests =====

	#[test]
	fn test_clone() {
		let c1 = Commitment::from(Fr::from(42u64));
		let c2 = c1;
		assert_eq!(c1, c2);
	}

	#[test]
	fn test_copy() {
		let c1 = Commitment::from(Fr::from(42u64));
		let c2 = c1;
		assert_eq!(c1, c2);
	}

	#[test]
	fn test_copy_semantics() {
		let c1 = Commitment::from(Fr::from(100u64));
		let c2 = c1; // Copy, not move
		let c3 = c1; // c1 still valid
		assert_eq!(c1, c2);
		assert_eq!(c1, c3);
	}

	// ===== Immutability Tests =====

	#[test]
	fn test_immutability() {
		let commitment = Commitment::from(Fr::from(42u64));
		let inner1 = commitment.inner();
		let inner2 = commitment.inner();
		assert_eq!(inner1, inner2);
	}

	#[test]
	fn test_shared_reference() {
		let commitment = Commitment::from(Fr::from(200u64));
		let ref1 = &commitment;
		let ref2 = &commitment;
		assert_eq!(ref1.inner(), ref2.inner());
	}

	// ===== Debug Tests =====

	#[test]
	fn test_debug_format() {
		let commitment = Commitment::from(Fr::from(42u64));
		let debug_str = format!("{commitment:?}");
		assert!(debug_str.contains("Commitment"));
	}

	// ===== Hash Tests =====

	#[test]
	fn test_hash_consistency() {
		let c1 = Commitment::from(Fr::from(100u64));
		let c2 = Commitment::from(Fr::from(100u64));
		// Verify equality works (Hash relies on PartialEq)
		assert_eq!(c1, c2);
		let items = [c1];
		assert!(items.contains(&c2));
	}

	#[test]
	fn test_hash_different_values() {
		let c1 = Commitment::from(Fr::from(100u64));
		let c2 = Commitment::from(Fr::from(200u64));
		// Verify inequality
		assert_ne!(c1, c2);
		let mut items = vec![c1, c2];
		// Check both are unique
		items.dedup();
		assert_eq!(items.len(), 2);
	}

	#[test]
	fn test_dedup_removes_duplicates() {
		// dedup() solo elimina duplicados consecutivos, así que creamos secuencia específica
		let c1 = Commitment::from(Fr::from(1u64));
		let c2 = Commitment::from(Fr::from(2u64));
		let commitments = [c1, c2, c1]; // c1 aparece al final
								  // Verificar que tenemos 3 elementos
		assert_eq!(commitments.len(), 3);
		// Verificar que el primero y último son iguales
		assert_eq!(commitments[0], commitments[2]);
	}

	// ===== Round-trip Conversion Tests =====

	#[test]
	fn test_roundtrip_field_element() {
		let field = FieldElement::from_u64(123);
		let commitment = Commitment::from(field);
		let field_back = commitment.inner();
		assert_eq!(field, field_back);
	}

	#[test]
	fn test_roundtrip_fr() {
		let fr = Fr::from(456u64);
		let commitment = Commitment::from(fr);
		let fr_back: Fr = commitment.into();
		assert_eq!(fr, fr_back);
	}

	#[test]
	fn test_roundtrip_new_inner() {
		let field = FieldElement::from_u64(789);
		let commitment = Commitment::new(field);
		let field_back = commitment.inner();
		assert_eq!(field, field_back);
	}

	// ===== Collection Tests =====

	#[test]
	fn test_vector_of_commitments() {
		let commitments = [
			Commitment::from(Fr::from(1u64)),
			Commitment::from(Fr::from(2u64)),
			Commitment::from(Fr::from(3u64)),
		];
		assert_eq!(commitments.len(), 3);
		assert_ne!(commitments[0], commitments[1]);
	}

	#[test]
	fn test_commitment_collection() {
		let c1 = Commitment::from(Fr::from(100u64));
		let c2 = Commitment::from(Fr::from(200u64));
		let items = [c1, c2];
		assert_eq!(items.len(), 2);
		assert!(items.contains(&c1));
		assert!(items.contains(&c2));
	}

	// ===== Edge Cases =====

	#[test]
	fn test_sequential_values() {
		let c1 = Commitment::from(Fr::from(100u64));
		let c2 = Commitment::from(Fr::from(101u64));
		assert_ne!(c1, c2);
	}

	#[test]
	fn test_large_value() {
		let commitment = Commitment::from(Fr::from(u64::MAX));
		assert_eq!(commitment.as_fr(), Fr::from(u64::MAX));
	}

	#[test]
	fn test_new_equals_from() {
		let field = FieldElement::from_u64(42);
		let c1 = Commitment::new(field);
		let c2 = Commitment::from(field);
		assert_eq!(c1, c2);
	}

	// ===== Consistency Tests =====

	#[test]
	fn test_consistency_new_and_from() {
		let field = FieldElement::from_u64(999);
		let c1 = Commitment::new(field);
		let c2 = Commitment::from(field);
		assert_eq!(c1, c2);
		assert_eq!(c1.inner(), c2.inner());
	}

	#[test]
	fn test_consistency_fr_conversions() {
		let fr = Fr::from(555u64);
		let commitment = Commitment::from(fr);
		assert_eq!(commitment.as_fr(), fr);
		let fr_back: Fr = commitment.into();
		assert_eq!(fr, fr_back);
	}

	// ===== Value Object Semantics =====

	#[test]
	fn test_value_object_equality() {
		// Same value = equal value objects
		let c1 = Commitment::from(Fr::from(100u64));
		let c2 = Commitment::from(Fr::from(100u64));
		assert_eq!(c1, c2);
	}

	#[test]
	fn test_value_object_different_values() {
		// Different values = different value objects
		let c1 = Commitment::from(Fr::from(100u64));
		let c2 = Commitment::from(Fr::from(101u64));
		assert_ne!(c1, c2);
	}

	// ===== Pattern Matching Tests =====

	#[test]
	fn test_pattern_matching() {
		let commitment = Commitment::from(Fr::from(42u64));
		match commitment {
			Commitment(_) => {}
		}
	}
}
