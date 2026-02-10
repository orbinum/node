//! Note Entity
//!
//! Private value representation in the shielded pool, containing value,
//! asset information, and cryptographic commitment data.

use crate::domain::{
	ports::PoseidonHasher,
	services::{CommitmentService, NullifierService},
	value_objects::{Blinding, Commitment, FieldElement, Nullifier, OwnerPubkey, SpendingKey},
};

/// Private note in the shielded pool
#[derive(Clone, Debug, PartialEq)]
pub struct Note {
	value: u64,
	asset_id: u64,
	/// Owner's public key (private)
	owner_pubkey: OwnerPubkey,
	/// Random blinding factor (private)
	blinding: Blinding,
}

impl Note {
	/// Create a new note with domain validation
	///
	/// # Domain Rules
	/// - Value can be zero (valid for dummy notes)
	/// - Asset ID 0 represents native token
	/// - Blinding should be generated from secure randomness
	///
	/// # Arguments
	/// - `value`: Token amount (u64)
	/// - `asset_id`: Asset identifier (u64)
	/// - `owner_pubkey`: Public key of the owner
	/// - `blinding`: Random blinding factor for unlinkability
	pub fn new(value: u64, asset_id: u64, owner_pubkey: OwnerPubkey, blinding: Blinding) -> Self {
		// Domain validation could go here
		// For now, all values are valid
		Self {
			value,
			asset_id,
			owner_pubkey,
			blinding,
		}
	}

	/// Create a zero note (for padding in circuits)
	///
	/// Zero notes are used in ZK circuits to pad input/output arrays
	/// to fixed sizes without revealing actual transaction structure.
	pub fn zero() -> Self {
		Self {
			value: 0,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(FieldElement::zero()),
			blinding: Blinding::from(FieldElement::zero()),
		}
	}

	/// Check if this is a zero note
	pub fn is_zero(&self) -> bool {
		self.value == 0
			&& self.asset_id == 0
			&& self.owner_pubkey.inner().is_zero()
			&& self.blinding.inner().is_zero()
	}

	// ========================================================================
	// Getters (Domain Encapsulation)
	// ========================================================================

	/// Get the value (read-only)
	pub fn value(&self) -> u64 {
		self.value
	}

	/// Get the asset ID (read-only)
	pub fn asset_id(&self) -> u64 {
		self.asset_id
	}

	/// Get the owner public key (read-only)
	pub fn owner_pubkey(&self) -> OwnerPubkey {
		self.owner_pubkey
	}

	/// Get the blinding factor (read-only)
	pub fn blinding(&self) -> Blinding {
		self.blinding
	}

	// ========================================================================
	// Domain Operations
	// ========================================================================

	/// Compute the commitment for this note
	///
	/// The commitment is the note's identifier in the Merkle tree.
	/// It hides all note details while allowing later verification.
	///
	/// # Domain Logic
	/// ```text
	/// commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
	/// ```
	pub fn commitment<H: PoseidonHasher>(&self, hasher: H) -> Commitment {
		let service = CommitmentService::new(hasher);
		service.create_commitment(self.value, self.asset_id, self.owner_pubkey, self.blinding)
	}

	/// Compute the nullifier for spending this note
	///
	/// The nullifier proves the note is spent without revealing which note.
	/// It can only be computed by the owner with the spending key.
	///
	/// # Domain Logic
	/// ```text
	/// nullifier = Poseidon(commitment, spending_key)
	/// ```
	///
	/// # Security
	/// - The spending key must be kept secret
	/// - Publishing the nullifier makes the note unspendable
	pub fn nullifier<H: PoseidonHasher + Clone>(
		&self,
		hasher: H,
		spending_key: &SpendingKey,
	) -> Nullifier {
		let commitment = self.commitment(hasher.clone());
		let service = NullifierService::new(hasher);
		service.compute_nullifier(&commitment, spending_key)
	}

	/// Check if this note can be spent by the given spending key
	///
	/// # Domain Rule
	/// A note can be spent if the spending key corresponds to the owner pubkey.
	/// In practice, this would involve cryptographic verification (not implemented here).
	pub fn can_spend_with(&self, _spending_key: &SpendingKey) -> bool {
		// In a real implementation, this would verify that spending_key
		// derives to owner_pubkey
		// For now, we assume the caller has already validated this
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::Fr;
	extern crate alloc;
	use alloc::format;

	// Mock hasher for testing
	#[derive(Clone)]
	struct MockHasher;

	impl PoseidonHasher for MockHasher {
		fn hash_2(&self, _inputs: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}

		fn hash_4(&self, _inputs: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
	}

	// ===== Construction Tests =====

	#[test]
	fn test_new() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 0, pubkey, blinding);
		assert_eq!(note.value(), 100);
		assert_eq!(note.asset_id(), 0);
		assert_eq!(note.owner_pubkey(), pubkey);
		assert_eq!(note.blinding(), blinding);
	}

	#[test]
	fn test_new_zero_value() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(0, 0, pubkey, blinding);
		assert_eq!(note.value(), 0);
	}

	#[test]
	fn test_new_max_value() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(u64::MAX, u64::MAX, pubkey, blinding);
		assert_eq!(note.value(), u64::MAX);
		assert_eq!(note.asset_id(), u64::MAX);
	}

	#[test]
	fn test_new_different_assets() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note1 = Note::new(100, 0, pubkey, blinding);
		let note2 = Note::new(100, 5, pubkey, blinding);
		let note3 = Note::new(100, 42, pubkey, blinding);
		assert_eq!(note1.asset_id(), 0);
		assert_eq!(note2.asset_id(), 5);
		assert_eq!(note3.asset_id(), 42);
	}

	#[test]
	fn test_new_different_pubkeys() {
		let pubkey1 = OwnerPubkey::from(Fr::from(100u64));
		let pubkey2 = OwnerPubkey::from(Fr::from(200u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note1 = Note::new(100, 0, pubkey1, blinding);
		let note2 = Note::new(100, 0, pubkey2, blinding);
		assert_ne!(note1.owner_pubkey(), note2.owner_pubkey());
	}

	#[test]
	fn test_new_different_blindings() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding1 = Blinding::from(Fr::from(100u64));
		let blinding2 = Blinding::from(Fr::from(200u64));
		let note1 = Note::new(100, 0, pubkey, blinding1);
		let note2 = Note::new(100, 0, pubkey, blinding2);
		assert_ne!(note1.blinding(), note2.blinding());
	}

	// ===== Zero Note Tests =====

	#[test]
	fn test_zero() {
		let note = Note::zero();
		assert!(note.is_zero());
		assert_eq!(note.value(), 0);
		assert_eq!(note.asset_id(), 0);
	}

	#[test]
	fn test_is_zero_true() {
		let note = Note::zero();
		assert!(note.is_zero());
	}

	#[test]
	fn test_is_zero_false_value() {
		let pubkey = OwnerPubkey::from(Fr::from(0u64));
		let blinding = Blinding::from(Fr::from(0u64));
		let note = Note::new(1, 0, pubkey, blinding);
		assert!(!note.is_zero());
	}

	#[test]
	fn test_is_zero_false_asset() {
		let pubkey = OwnerPubkey::from(Fr::from(0u64));
		let blinding = Blinding::from(Fr::from(0u64));
		let note = Note::new(0, 1, pubkey, blinding);
		assert!(!note.is_zero());
	}

	#[test]
	fn test_is_zero_false_pubkey() {
		let pubkey = OwnerPubkey::from(Fr::from(1u64));
		let blinding = Blinding::from(Fr::from(0u64));
		let note = Note::new(0, 0, pubkey, blinding);
		assert!(!note.is_zero());
	}

	#[test]
	fn test_is_zero_false_blinding() {
		let pubkey = OwnerPubkey::from(Fr::from(0u64));
		let blinding = Blinding::from(Fr::from(1u64));
		let note = Note::new(0, 0, pubkey, blinding);
		assert!(!note.is_zero());
	}

	// ===== Getter Tests =====

	#[test]
	fn test_value() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(12345, 0, pubkey, blinding);
		assert_eq!(note.value(), 12345);
	}

	#[test]
	fn test_asset_id() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 99, pubkey, blinding);
		assert_eq!(note.asset_id(), 99);
	}

	#[test]
	fn test_owner_pubkey() {
		let pubkey = OwnerPubkey::from(Fr::from(999u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 0, pubkey, blinding);
		assert_eq!(note.owner_pubkey(), pubkey);
	}

	#[test]
	fn test_blinding() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(888u64));
		let note = Note::new(100, 0, pubkey, blinding);
		assert_eq!(note.blinding(), blinding);
	}

	// ===== Commitment Tests =====

	#[test]
	fn test_commitment() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 0, pubkey, blinding);
		let commitment = note.commitment(MockHasher);
		// MockHasher returns 100 for hash_4
		assert_eq!(commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_commitment_deterministic() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 0, pubkey, blinding);
		let commitment1 = note.commitment(MockHasher);
		let commitment2 = note.commitment(MockHasher);
		assert_eq!(commitment1, commitment2);
	}

	#[test]
	fn test_commitment_zero_note() {
		let note = Note::zero();
		let commitment = note.commitment(MockHasher);
		assert_eq!(commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_commitment_large_value() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(u64::MAX, u64::MAX, pubkey, blinding);
		let commitment = note.commitment(MockHasher);
		assert_eq!(commitment, Commitment::from(Fr::from(100u64)));
	}

	#[test]
	fn test_commitment_different_notes() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note1 = Note::new(100, 0, pubkey, blinding);
		let note2 = Note::new(200, 0, pubkey, blinding);
		let c1 = note1.commitment(MockHasher);
		let c2 = note2.commitment(MockHasher);
		// MockHasher returns same value, real impl would differ
		assert_eq!(c1, c2);
	}

	// ===== Nullifier Tests =====

	#[test]
	fn test_nullifier() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let spending_key = SpendingKey::from(Fr::from(789u64));
		let note = Note::new(100, 0, pubkey, blinding);
		let nullifier = note.nullifier(MockHasher, &spending_key);
		// MockHasher returns 42 for hash_2
		assert_eq!(nullifier, Nullifier::from(Fr::from(42u64)));
	}

	#[test]
	fn test_nullifier_deterministic() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let spending_key = SpendingKey::from(Fr::from(789u64));
		let note = Note::new(100, 0, pubkey, blinding);
		let nullifier1 = note.nullifier(MockHasher, &spending_key);
		let nullifier2 = note.nullifier(MockHasher, &spending_key);
		assert_eq!(nullifier1, nullifier2);
	}

	#[test]
	fn test_nullifier_zero_note() {
		let note = Note::zero();
		let spending_key = SpendingKey::from(Fr::from(123u64));
		let nullifier = note.nullifier(MockHasher, &spending_key);
		assert_eq!(nullifier, Nullifier::from(Fr::from(42u64)));
	}

	#[test]
	fn test_nullifier_different_keys() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let key1 = SpendingKey::from(Fr::from(100u64));
		let key2 = SpendingKey::from(Fr::from(200u64));
		let note = Note::new(100, 0, pubkey, blinding);
		let nullifier1 = note.nullifier(MockHasher, &key1);
		let nullifier2 = note.nullifier(MockHasher, &key2);
		// MockHasher returns same, real impl would differ
		assert_eq!(nullifier1, nullifier2);
	}

	#[test]
	fn test_nullifier_different_notes_same_key() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let spending_key = SpendingKey::from(Fr::from(789u64));
		let note1 = Note::new(100, 0, pubkey, blinding);
		let note2 = Note::new(200, 0, pubkey, blinding);
		let nullifier1 = note1.nullifier(MockHasher, &spending_key);
		let nullifier2 = note2.nullifier(MockHasher, &spending_key);
		// MockHasher returns same, real impl would differ
		assert_eq!(nullifier1, nullifier2);
	}

	// ===== Can Spend Tests =====

	#[test]
	fn test_can_spend_with() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let spending_key = SpendingKey::from(Fr::from(789u64));
		let note = Note::new(100, 0, pubkey, blinding);
		assert!(note.can_spend_with(&spending_key));
	}

	#[test]
	fn test_can_spend_with_zero_note() {
		let note = Note::zero();
		let spending_key = SpendingKey::from(Fr::from(123u64));
		assert!(note.can_spend_with(&spending_key));
	}

	#[test]
	fn test_can_spend_with_different_keys() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let key1 = SpendingKey::from(Fr::from(100u64));
		let key2 = SpendingKey::from(Fr::from(200u64));
		let note = Note::new(100, 0, pubkey, blinding);
		// Current impl always returns true
		assert!(note.can_spend_with(&key1));
		assert!(note.can_spend_with(&key2));
	}

	// ===== Clone and Equality Tests =====

	#[test]
	fn test_clone() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note1 = Note::new(100, 0, pubkey, blinding);
		let note2 = note1.clone();
		assert_eq!(note1, note2);
	}

	#[test]
	fn test_partial_eq_equal() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note1 = Note::new(100, 0, pubkey, blinding);
		let note2 = Note::new(100, 0, pubkey, blinding);
		assert_eq!(note1, note2);
	}

	#[test]
	fn test_partial_eq_different_value() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note1 = Note::new(100, 0, pubkey, blinding);
		let note2 = Note::new(200, 0, pubkey, blinding);
		assert_ne!(note1, note2);
	}

	#[test]
	fn test_partial_eq_different_asset() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note1 = Note::new(100, 0, pubkey, blinding);
		let note2 = Note::new(100, 5, pubkey, blinding);
		assert_ne!(note1, note2);
	}

	#[test]
	fn test_partial_eq_different_pubkey() {
		let pubkey1 = OwnerPubkey::from(Fr::from(100u64));
		let pubkey2 = OwnerPubkey::from(Fr::from(200u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note1 = Note::new(100, 0, pubkey1, blinding);
		let note2 = Note::new(100, 0, pubkey2, blinding);
		assert_ne!(note1, note2);
	}

	#[test]
	fn test_partial_eq_different_blinding() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding1 = Blinding::from(Fr::from(100u64));
		let blinding2 = Blinding::from(Fr::from(200u64));
		let note1 = Note::new(100, 0, pubkey, blinding1);
		let note2 = Note::new(100, 0, pubkey, blinding2);
		assert_ne!(note1, note2);
	}

	#[test]
	fn test_debug() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 0, pubkey, blinding);
		let debug_str = format!("{note:?}");
		assert!(debug_str.contains("Note"));
	}

	// ===== Encapsulation Tests =====

	#[test]
	fn test_encapsulation() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let note = Note::new(100, 0, pubkey, blinding);
		// All fields are private, only accessible via getters
		assert_eq!(note.value(), 100);
		assert_eq!(note.asset_id(), 0);
	}
}
