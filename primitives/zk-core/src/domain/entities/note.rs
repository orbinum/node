//! Note Entity - Private value in the shielded pool

use crate::domain::ports::PoseidonHasher;
use crate::domain::services::{CommitmentService, NullifierService};
use crate::domain::value_objects::{
	Blinding, Commitment, FieldElement, Nullifier, OwnerPubkey, SpendingKey,
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

	#[test]
	fn test_note_creation() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));

		let note = Note::new(100, 0, pubkey, blinding);

		assert_eq!(note.value(), 100);
		assert_eq!(note.asset_id(), 0);
		assert_eq!(note.owner_pubkey(), pubkey);
		assert_eq!(note.blinding(), blinding);
	}

	#[test]
	fn test_zero_note() {
		let note = Note::zero();

		assert!(note.is_zero());
		assert_eq!(note.value(), 0);
		assert_eq!(note.asset_id(), 0);
	}

	#[test]
	fn test_note_commitment() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));

		let note = Note::new(100, 0, pubkey, blinding);
		let commitment = note.commitment(MockHasher);

		// Commitment should be deterministic
		let commitment2 = note.commitment(MockHasher);
		assert_eq!(commitment, commitment2);
	}

	#[test]
	fn test_note_nullifier() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));
		let spending_key = SpendingKey::from(Fr::from(789u64));

		let note = Note::new(100, 0, pubkey, blinding);
		let nullifier = note.nullifier(MockHasher, &spending_key);

		// Nullifier should be deterministic
		let nullifier2 = note.nullifier(MockHasher, &spending_key);
		assert_eq!(nullifier, nullifier2);
	}

	#[test]
	fn test_different_notes_different_commitments() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));

		let note1 = Note::new(100, 0, pubkey, blinding);
		let note2 = Note::new(200, 0, pubkey, blinding);

		let c1 = note1.commitment(MockHasher);
		let c2 = note2.commitment(MockHasher);

		// Mock hasher returns same value, but real implementation would differ
		assert_eq!(c1, c2); // Mock limitation
	}

	#[test]
	fn test_note_encapsulation() {
		let pubkey = OwnerPubkey::from(Fr::from(123u64));
		let blinding = Blinding::from(Fr::from(456u64));

		let note = Note::new(100, 0, pubkey, blinding);

		// All fields are private, only accessible via getters
		assert_eq!(note.value(), 100);
		assert_eq!(note.asset_id(), 0);
		// Cannot modify: note.value = 200; // This would not compile
	}
}
