//! # Spending Key Value Object
//!
//! Represents the private key required to spend a note.
//! Must be kept secret by the note owner.

use crate::domain::value_objects::field_element::FieldElement;
use ark_bn254::Fr;

/// A private spending key for spending notes
///
/// ## DDD Value Object Properties
/// - Immutable: Once created, cannot be modified
/// - Secret: Must never be exposed publicly
/// - Self-validating: Validates its own invariants
///
/// ## Domain Semantics
/// The spending key is the private key that allows spending a note.
/// It is used to compute the nullifier:
/// ```text
/// nullifier = Poseidon(commitment, spending_key)
/// ```
///
/// ## Security
/// - Should be generated from a secure random source
/// - Must be stored securely (encrypted wallet, HSM, etc.)
/// - Never transmitted in plaintext
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

	/// Generate from u64 (for testing only, not cryptographically secure)
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

	#[test]
	fn test_spending_key_creation() {
		let field = FieldElement::from_u64(42);
		let key = SpendingKey::new(field);
		assert_eq!(key.inner(), field);
	}

	#[test]
	fn test_spending_key_equality() {
		let key1 = SpendingKey::from_u64(100);
		let key2 = SpendingKey::from_u64(100);
		let key3 = SpendingKey::from_u64(200);

		assert_eq!(key1, key2);
		assert_ne!(key1, key3);
	}

	#[test]
	fn test_spending_key_immutability() {
		let key = SpendingKey::from(Fr::from(42u64));
		let inner = key.inner();

		// Key cannot be modified, only cloned
		let key2 = key;
		assert_eq!(key, key2);
		assert_eq!(key.inner(), inner);
	}
}
