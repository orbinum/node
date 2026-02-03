//! # Owner Public Key Value Object
//!
//! Represents the public key of a note owner.
//! Used in commitment computation and note ownership verification.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// A public key identifying the owner of a note
///
/// ## DDD Value Object Properties
/// - Immutable: Once created, cannot be modified
/// - Public: Can be shared without compromising security
/// - Self-validating: Validates its own invariants
///
/// ## Domain Semantics
/// The owner public key is part of the note commitment:
/// ```text
/// commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
/// ```
///
/// It identifies who can spend the note (whoever has the corresponding
/// spending key).
///
/// ## Usage
/// - Derived from the owner's spending key
/// - Included in note commitments
/// - Used to verify note ownership
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

	#[test]
	fn test_owner_pubkey_creation() {
		let field = FieldElement::from_u64(42);
		let pubkey = OwnerPubkey::new(field);
		assert_eq!(pubkey.inner(), field);
	}

	#[test]
	fn test_owner_pubkey_equality() {
		let pk1 = OwnerPubkey::from_u64(100);
		let pk2 = OwnerPubkey::from_u64(100);
		let pk3 = OwnerPubkey::from_u64(200);

		assert_eq!(pk1, pk2);
		assert_ne!(pk1, pk3);
	}

	#[test]
	fn test_owner_pubkey_immutability() {
		let pubkey = OwnerPubkey::from(Fr::from(42u64));
		let inner = pubkey.inner();

		// Pubkey cannot be modified, only cloned
		let pubkey2 = pubkey;
		assert_eq!(pubkey, pubkey2);
		assert_eq!(pubkey.inner(), inner);
	}
}
