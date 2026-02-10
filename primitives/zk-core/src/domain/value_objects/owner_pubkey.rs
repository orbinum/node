//! Owner Public Key Value Object
//!
//! Public key identifying the owner of a note, used in commitment computation.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// Public key identifying the owner of a note
///
/// Used in commitment: `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OwnerPubkey(FieldElement);

impl OwnerPubkey {
	/// Create a new owner public key from field element
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

impl From<FieldElement> for OwnerPubkey {
	fn from(value: FieldElement) -> Self {
		Self(value)
	}
}

impl From<Fr> for OwnerPubkey {
	fn from(value: Fr) -> Self {
		Self(FieldElement::new(value))
	}
}

impl From<OwnerPubkey> for Fr {
	fn from(pubkey: OwnerPubkey) -> Self {
		pubkey.as_fr()
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
		let pubkey = OwnerPubkey::new(field);
		assert_eq!(pubkey.inner(), field);
	}

	#[test]
	fn test_new_zero() {
		let field = FieldElement::from_u64(0);
		let pubkey = OwnerPubkey::new(field);
		assert_eq!(pubkey.inner(), field);
	}

	#[test]
	fn test_new_max() {
		let field = FieldElement::from_u64(u64::MAX);
		let pubkey = OwnerPubkey::new(field);
		assert_eq!(pubkey.inner(), field);
	}

	#[test]
	fn test_from_u64() {
		let pubkey = OwnerPubkey::from_u64(123);
		assert_eq!(pubkey.inner(), FieldElement::from_u64(123));
	}

	#[test]
	fn test_from_u64_zero() {
		let pubkey = OwnerPubkey::from_u64(0);
		assert_eq!(pubkey.inner(), FieldElement::from_u64(0));
	}

	#[test]
	fn test_from_u64_max() {
		let pubkey = OwnerPubkey::from_u64(u64::MAX);
		assert_eq!(pubkey.inner(), FieldElement::from_u64(u64::MAX));
	}

	// ===== Getter Tests =====

	#[test]
	fn test_inner() {
		let field = FieldElement::from_u64(42);
		let pubkey = OwnerPubkey::new(field);
		assert_eq!(pubkey.inner(), field);
	}

	#[test]
	fn test_as_fr() {
		let fr = Fr::from(100u64);
		let pubkey = OwnerPubkey::from(fr);
		assert_eq!(pubkey.as_fr(), fr);
	}

	#[test]
	fn test_inner_consistency() {
		let field = FieldElement::from_u64(999);
		let pubkey = OwnerPubkey::new(field);
		assert_eq!(pubkey.inner().inner(), field.inner());
	}

	// ===== Equality Tests =====

	#[test]
	fn test_equality_same_value() {
		let pk1 = OwnerPubkey::from_u64(100);
		let pk2 = OwnerPubkey::from_u64(100);
		assert_eq!(pk1, pk2);
	}

	#[test]
	fn test_inequality_different_value() {
		let pk1 = OwnerPubkey::from_u64(100);
		let pk2 = OwnerPubkey::from_u64(200);
		assert_ne!(pk1, pk2);
	}

	#[test]
	fn test_equality_zero() {
		let pk1 = OwnerPubkey::from_u64(0);
		let pk2 = OwnerPubkey::from_u64(0);
		assert_eq!(pk1, pk2);
	}

	#[test]
	fn test_equality_max() {
		let pk1 = OwnerPubkey::from_u64(u64::MAX);
		let pk2 = OwnerPubkey::from_u64(u64::MAX);
		assert_eq!(pk1, pk2);
	}

	// ===== From Trait Tests =====

	#[test]
	fn test_from_field_element() {
		let field = FieldElement::from_u64(42);
		let pubkey = OwnerPubkey::from(field);
		assert_eq!(pubkey.inner(), field);
	}

	#[test]
	fn test_from_fr() {
		let fr = Fr::from(100u64);
		let pubkey = OwnerPubkey::from(fr);
		assert_eq!(pubkey.as_fr(), fr);
	}

	#[test]
	fn test_from_fr_zero() {
		let fr = Fr::from(0u64);
		let pubkey = OwnerPubkey::from(fr);
		assert_eq!(pubkey.as_fr(), fr);
	}

	#[test]
	fn test_into_fr() {
		let pubkey = OwnerPubkey::from_u64(123);
		let fr: Fr = pubkey.into();
		assert_eq!(fr, Fr::from(123u64));
	}

	#[test]
	fn test_into_fr_zero() {
		let pubkey = OwnerPubkey::from_u64(0);
		let fr: Fr = pubkey.into();
		assert_eq!(fr, Fr::from(0u64));
	}

	// ===== Clone and Copy Tests =====

	#[test]
	fn test_clone() {
		let pk1 = OwnerPubkey::from_u64(42);
		let pk2 = pk1;
		assert_eq!(pk1, pk2);
	}

	#[test]
	fn test_copy() {
		let pk1 = OwnerPubkey::from_u64(42);
		let pk2 = pk1;
		assert_eq!(pk1, pk2);
	}

	#[test]
	fn test_copy_semantics() {
		let pk1 = OwnerPubkey::from_u64(100);
		let pk2 = pk1; // Copy, not move
		let pk3 = pk1; // pk1 still valid
		assert_eq!(pk1, pk2);
		assert_eq!(pk1, pk3);
	}

	// ===== Immutability Tests =====

	#[test]
	fn test_immutability() {
		let pubkey = OwnerPubkey::from(Fr::from(42u64));
		let inner1 = pubkey.inner();
		let inner2 = pubkey.inner();
		assert_eq!(inner1, inner2);
	}

	#[test]
	fn test_shared_reference() {
		let pubkey = OwnerPubkey::from_u64(200);
		let ref1 = &pubkey;
		let ref2 = &pubkey;
		assert_eq!(ref1.inner(), ref2.inner());
	}

	// ===== Debug Tests =====

	#[test]
	fn test_debug_format() {
		let pubkey = OwnerPubkey::from_u64(42);
		let debug_str = format!("{pubkey:?}");
		assert!(debug_str.contains("OwnerPubkey"));
	}

	// ===== Hash Tests =====

	#[test]
	fn test_hash_consistency() {
		let pk1 = OwnerPubkey::from_u64(100);
		let pk2 = OwnerPubkey::from_u64(100);
		assert_eq!(pk1, pk2);
		let items = [pk1];
		assert!(items.contains(&pk2));
	}

	#[test]
	fn test_hash_different_values() {
		let pk1 = OwnerPubkey::from_u64(100);
		let pk2 = OwnerPubkey::from_u64(200);
		assert_ne!(pk1, pk2);
		let mut items = vec![pk1, pk2];
		items.dedup();
		assert_eq!(items.len(), 2);
	}

	#[test]
	fn test_dedup_removes_duplicates() {
		let pk1 = OwnerPubkey::from_u64(1);
		let pk2 = OwnerPubkey::from_u64(2);
		let pubkeys = [pk1, pk2, pk1];
		assert_eq!(pubkeys.len(), 3);
		assert_eq!(pubkeys[0], pubkeys[2]);
	}

	// ===== Round-trip Conversion Tests =====

	#[test]
	fn test_roundtrip_field_element() {
		let field = FieldElement::from_u64(123);
		let pubkey = OwnerPubkey::from(field);
		let field_back = pubkey.inner();
		assert_eq!(field, field_back);
	}

	#[test]
	fn test_roundtrip_fr() {
		let fr = Fr::from(456u64);
		let pubkey = OwnerPubkey::from(fr);
		let fr_back: Fr = pubkey.into();
		assert_eq!(fr, fr_back);
	}

	#[test]
	fn test_roundtrip_new_inner() {
		let field = FieldElement::from_u64(789);
		let pubkey = OwnerPubkey::new(field);
		let field_back = pubkey.inner();
		assert_eq!(field, field_back);
	}

	// ===== Collection Tests =====

	#[test]
	fn test_vector_of_pubkeys() {
		let pubkeys = [
			OwnerPubkey::from_u64(1),
			OwnerPubkey::from_u64(2),
			OwnerPubkey::from_u64(3),
		];
		assert_eq!(pubkeys.len(), 3);
		assert_ne!(pubkeys[0], pubkeys[1]);
	}

	#[test]
	fn test_pubkey_collection() {
		let pk1 = OwnerPubkey::from_u64(100);
		let pk2 = OwnerPubkey::from_u64(200);
		let items = [pk1, pk2];
		assert_eq!(items.len(), 2);
		assert!(items.contains(&pk1));
		assert!(items.contains(&pk2));
	}

	// ===== Edge Cases =====

	#[test]
	fn test_sequential_values() {
		let pk1 = OwnerPubkey::from_u64(100);
		let pk2 = OwnerPubkey::from_u64(101);
		assert_ne!(pk1, pk2);
	}

	#[test]
	fn test_large_value() {
		let pubkey = OwnerPubkey::from_u64(1_000_000_000);
		assert_eq!(pubkey.inner(), FieldElement::from_u64(1_000_000_000));
	}

	#[test]
	fn test_new_equals_from() {
		let field = FieldElement::from_u64(42);
		let pk1 = OwnerPubkey::new(field);
		let pk2 = OwnerPubkey::from(field);
		assert_eq!(pk1, pk2);
	}

	// ===== Consistency Tests =====

	#[test]
	fn test_consistency_new_and_from() {
		let field = FieldElement::from_u64(999);
		let pk1 = OwnerPubkey::new(field);
		let pk2 = OwnerPubkey::from(field);
		assert_eq!(pk1, pk2);
		assert_eq!(pk1.inner(), pk2.inner());
	}

	#[test]
	fn test_consistency_fr_conversions() {
		let fr = Fr::from(555u64);
		let pubkey = OwnerPubkey::from(fr);
		assert_eq!(pubkey.as_fr(), fr);
		let fr_back: Fr = pubkey.into();
		assert_eq!(fr, fr_back);
	}

	// ===== Value Object Semantics =====

	#[test]
	fn test_value_object_equality() {
		let pk1 = OwnerPubkey::from(Fr::from(100u64));
		let pk2 = OwnerPubkey::from(Fr::from(100u64));
		assert_eq!(pk1, pk2);
	}

	#[test]
	fn test_value_object_different_values() {
		let pk1 = OwnerPubkey::from(Fr::from(100u64));
		let pk2 = OwnerPubkey::from(Fr::from(101u64));
		assert_ne!(pk1, pk2);
	}

	// ===== Pattern Matching Tests =====

	#[test]
	fn test_pattern_matching() {
		let pubkey = OwnerPubkey::from_u64(42);
		match pubkey {
			OwnerPubkey(_) => {}
		}
	}
}
