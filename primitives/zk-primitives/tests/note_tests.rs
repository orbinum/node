//! Integration tests for Note structure and operations

use ark_bn254::Fr as Bn254Fr;
use fp_zk_primitives::core::constants::NATIVE_ASSET_ID;
use fp_zk_primitives::core::types::SpendingKey;
use fp_zk_primitives::models::note::Note;

#[test]
fn test_note_creation() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note = Note::new(100, 0, owner, blinding);

	assert_eq!(note.value, Bn254Fr::from(100u64));
	assert_eq!(note.asset_id, Bn254Fr::from(0u64));
	assert_eq!(note.owner_pubkey, owner);
	assert_eq!(note.blinding, blinding);
}

#[test]
fn test_note_creation_from_fields() {
	let value = Bn254Fr::from(100u64);
	let asset_id = Bn254Fr::from(1u64);
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note = Note::from_fields(value, asset_id, owner, blinding);

	assert_eq!(note.value, value);
	assert_eq!(note.asset_id, asset_id);
	assert_eq!(note.owner_pubkey, owner);
	assert_eq!(note.blinding, blinding);
}

#[test]
fn test_note_commitment() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note = Note::new(100, 0, owner, blinding);
	let commitment = note.commitment();

	// Commitment should be non-zero
	assert_ne!(commitment.0, Bn254Fr::from(0u64));

	// Same note should produce same commitment
	let commitment2 = note.commitment();
	assert_eq!(commitment.0, commitment2.0);
}

#[test]
fn test_note_nullifier() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);
	let spending_key = SpendingKey(Bn254Fr::from(11111u64));

	let note = Note::new(100, 0, owner, blinding);
	let nullifier = note.nullifier(&spending_key);

	// Nullifier should be non-zero
	assert_ne!(nullifier.0, Bn254Fr::from(0u64));

	// Nullifier should be different from commitment
	assert_ne!(nullifier.0, note.commitment().0);

	// Same inputs should produce same nullifier
	let nullifier2 = note.nullifier(&spending_key);
	assert_eq!(nullifier.0, nullifier2.0);
}

#[test]
fn test_zero_note() {
	let zero = Note::zero();

	assert_eq!(zero.value, Bn254Fr::from(0u64));
	assert_eq!(zero.asset_id, Bn254Fr::from(0u64));
	assert_eq!(zero.owner_pubkey, Bn254Fr::from(0u64));
	assert_eq!(zero.blinding, Bn254Fr::from(0u64));
}

#[test]
fn test_note_equality() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note1 = Note::new(100, 0, owner, blinding);
	let note2 = Note::new(100, 0, owner, blinding);
	let note3 = Note::new(200, 0, owner, blinding);

	assert_eq!(note1, note2);
	assert_ne!(note1, note3);
}

#[test]
fn test_different_notes_different_commitments() {
	let owner = Bn254Fr::from(12345u64);
	let blinding1 = Bn254Fr::from(11111u64);
	let blinding2 = Bn254Fr::from(22222u64);

	let note1 = Note::new(100, 0, owner, blinding1);
	let note2 = Note::new(100, 0, owner, blinding2);

	// Different blindings should produce different commitments
	assert_ne!(note1.commitment().0, note2.commitment().0);
}

#[test]
fn test_value_u64_conversion() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note = Note::new(100, 0, owner, blinding);

	assert_eq!(note.value_u64(), Some(100u64));
}

#[test]
fn test_asset_id_u64_conversion() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note = Note::new(100, 42, owner, blinding);

	assert_eq!(note.asset_id_u64(), Some(42u64));
}

#[test]
fn test_note_with_native_asset() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note = Note::new(1000, NATIVE_ASSET_ID, owner, blinding);

	assert_eq!(note.asset_id_u64(), Some(NATIVE_ASSET_ID));
}

#[test]
fn test_note_with_large_value() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);
	let large_value = 1_000_000_000u64;

	let note = Note::new(large_value, 0, owner, blinding);

	assert_eq!(note.value_u64(), Some(large_value));
}

#[test]
fn test_note_clone() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note1 = Note::new(100, 0, owner, blinding);
	let note2 = note1.clone();

	assert_eq!(note1, note2);
	assert_eq!(note1.commitment().0, note2.commitment().0);
}

#[test]
fn test_multiple_notes_with_same_owner() {
	let owner = Bn254Fr::from(12345u64);
	let blinding1 = Bn254Fr::from(11111u64);
	let blinding2 = Bn254Fr::from(22222u64);
	let blinding3 = Bn254Fr::from(33333u64);

	let note1 = Note::new(100, 0, owner, blinding1);
	let note2 = Note::new(200, 0, owner, blinding2);
	let note3 = Note::new(300, 0, owner, blinding3);

	// All notes have same owner but different values and blindings
	assert_eq!(note1.owner_pubkey, owner);
	assert_eq!(note2.owner_pubkey, owner);
	assert_eq!(note3.owner_pubkey, owner);

	// But different commitments
	assert_ne!(note1.commitment().0, note2.commitment().0);
	assert_ne!(note1.commitment().0, note3.commitment().0);
	assert_ne!(note2.commitment().0, note3.commitment().0);
}

#[test]
fn test_note_nullifier_with_different_keys() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);
	let key1 = SpendingKey(Bn254Fr::from(11111u64));
	let key2 = SpendingKey(Bn254Fr::from(22222u64));

	let note = Note::new(100, 0, owner, blinding);

	let nullifier1 = note.nullifier(&key1);
	let nullifier2 = note.nullifier(&key2);

	// Different spending keys produce different nullifiers
	assert_ne!(nullifier1.0, nullifier2.0);
}

#[test]
fn test_complete_note_workflow() {
	// Simulate complete note lifecycle
	let owner = Bn254Fr::from(55555u64);
	let blinding = Bn254Fr::from(77777u64);
	let spending_key = SpendingKey(Bn254Fr::from(88888u64));

	// 1. Create note
	let note = Note::new(500, NATIVE_ASSET_ID, owner, blinding);
	assert_eq!(note.value_u64(), Some(500));
	assert_eq!(note.asset_id_u64(), Some(NATIVE_ASSET_ID));

	// 2. Get commitment (for inserting into Merkle tree)
	let commitment = note.commitment();
	assert_ne!(commitment.0, Bn254Fr::from(0u64));

	// 3. Later, when spending, compute nullifier
	let nullifier = note.nullifier(&spending_key);
	assert_ne!(nullifier.0, Bn254Fr::from(0u64));
	assert_ne!(nullifier.0, commitment.0);

	// 4. Verify determinism
	let commitment2 = note.commitment();
	let nullifier2 = note.nullifier(&spending_key);
	assert_eq!(commitment.0, commitment2.0);
	assert_eq!(nullifier.0, nullifier2.0);
}

#[test]
fn test_note_debug_format() {
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);
	let note = Note::new(100, 0, owner, blinding);

	// Should be able to debug print
	let debug_str = format!("{:?}", note);
	assert!(debug_str.contains("Note"));
}
