//! Tests for note

use crate::domain::{entities::Note, value_objects::Hash};

fn sample_pubkey() -> Hash {
	[42u8; 32]
}

fn sample_blinding() -> Hash {
	[99u8; 32]
}

#[test]
fn test_note_creation() {
	let note = Note::new(1000, sample_pubkey(), sample_blinding()).unwrap();
	assert_eq!(note.value(), 1000);
	assert_eq!(note.owner_pubkey(), &sample_pubkey());
	assert_eq!(note.blinding(), &sample_blinding());
	assert_eq!(note.asset_id(), 0);
}

#[test]
fn test_note_validation() {
	let note = Note::new(1000, sample_pubkey(), sample_blinding()).unwrap();
	assert!(note.is_valid());
}

#[test]
fn test_note_zero_value_fails() {
	let result = Note::new(0, sample_pubkey(), sample_blinding());
	assert!(result.is_err());
	assert_eq!(result.unwrap_err(), "Note value cannot be zero");
}

#[test]
fn test_note_zero_pubkey_fails() {
	let result = Note::new(1000, [0u8; 32], sample_blinding());
	assert!(result.is_err());
	assert_eq!(result.unwrap_err(), "Owner public key cannot be zero");
}

#[test]
fn test_note_zero_blinding_fails() {
	let result = Note::new(1000, sample_pubkey(), [0u8; 32]);
	assert!(result.is_err());
	assert_eq!(result.unwrap_err(), "Blinding factor cannot be zero");
}

#[test]
fn test_note_with_asset() {
	let note = Note::new_with_asset(500, sample_pubkey(), sample_blinding(), 42).unwrap();
	assert_eq!(note.value(), 500);
	assert_eq!(note.asset_id(), 42);
}

#[test]
fn test_note_serialization() {
	let note = Note::new(1000, sample_pubkey(), sample_blinding()).unwrap();
	let bytes = note.to_bytes();

	// Verificar longitud: 16 (value u128) + 32 (pubkey) + 32 (blinding) + 8 (asset_id u64)
	assert_eq!(bytes.len(), 88);

	// Verificar que contiene el valor (u128 = 16 bytes)
	let value_bytes = &bytes[0..16];
	assert_eq!(u128::from_le_bytes(value_bytes.try_into().unwrap()), 1000);
}

#[test]
fn test_note_equality() {
	let note1 = Note::new(1000, sample_pubkey(), sample_blinding()).unwrap();
	let note2 = Note::new(1000, sample_pubkey(), sample_blinding()).unwrap();
	let note3 = Note::new(2000, sample_pubkey(), sample_blinding()).unwrap();

	assert_eq!(note1, note2);
	assert_ne!(note1, note3);
}
