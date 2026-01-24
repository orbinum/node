//! Tests for key derivation functions

use fp_encrypted_memo::crypto::key_derivation::derive_encryption_key;
use fp_encrypted_memo::*;

fn sample_viewing_key() -> [u8; 32] {
	[42u8; 32]
}

fn sample_commitment() -> [u8; 32] {
	[99u8; 32]
}

fn sample_spending_key() -> [u8; 32] {
	[0xDE; 32]
}

#[test]
fn test_derive_encryption_key_deterministic() {
	let vk = sample_viewing_key();
	let commitment = sample_commitment();

	let key1 = derive_encryption_key(&vk, &commitment);
	let key2 = derive_encryption_key(&vk, &commitment);

	assert_eq!(key1, key2);
}

#[test]
fn test_derive_encryption_key_different_inputs() {
	let vk1 = [1u8; 32];
	let vk2 = [2u8; 32];
	let commitment = sample_commitment();

	let key1 = derive_encryption_key(&vk1, &commitment);
	let key2 = derive_encryption_key(&vk2, &commitment);

	assert_ne!(key1, key2);
}

#[test]
fn test_viewing_key_derivation() {
	let spending_key = sample_spending_key();
	let vk = ViewingKey::from_spending_key(&spending_key);

	// Should be 32 bytes
	assert_eq!(vk.as_bytes().len(), 32);

	// Should not be the same as spending key
	assert_ne!(vk.as_bytes(), &spending_key);
}

#[test]
fn test_viewing_key_deterministic() {
	let spending_key = sample_spending_key();

	let vk1 = ViewingKey::from_spending_key(&spending_key);
	let vk2 = ViewingKey::from_spending_key(&spending_key);

	assert_eq!(vk1, vk2);
}

#[test]
fn test_viewing_key_different_spending_keys() {
	let sk1 = [1u8; 32];
	let sk2 = [2u8; 32];

	let vk1 = ViewingKey::from_spending_key(&sk1);
	let vk2 = ViewingKey::from_spending_key(&sk2);

	assert_ne!(vk1, vk2);
}

#[test]
fn test_nullifier_key_derivation() {
	let spending_key = sample_spending_key();
	let nk = NullifierKey::from_spending_key(&spending_key);

	// Should be 32 bytes
	assert_eq!(nk.as_bytes().len(), 32);

	// Should not be the same as spending key
	assert_ne!(nk.as_bytes(), &spending_key);

	// Should not be the same as viewing key
	let vk = ViewingKey::from_spending_key(&spending_key);
	assert_ne!(nk.as_bytes(), vk.as_bytes());
}

#[test]
fn test_derive_viewing_key_function() {
	let spending_key = sample_spending_key();

	let vk1 = derive_viewing_key(&spending_key);
	let vk2 = ViewingKey::from_spending_key(&spending_key);

	assert_eq!(vk1, *vk2.as_bytes());
}

#[test]
fn test_viewing_key_from_bytes() {
	let bytes = [0xAB; 32];
	let vk = ViewingKey::from_bytes(bytes);
	assert_eq!(vk.as_bytes(), &bytes);

	// Test From trait
	let vk2: ViewingKey = bytes.into();
	assert_eq!(vk, vk2);
}

#[test]
fn test_eddsa_key_derivation() {
	let spending_key = [0xAB; 32];

	// Test convenience function
	let eddsa_key1 = derive_eddsa_key(&spending_key);

	// Test EdDSAKey type
	let eddsa_key2 = EdDSAKey::from_spending_key(&spending_key);

	// Both methods should produce the same result
	assert_eq!(eddsa_key1, *eddsa_key2.as_bytes());

	// EdDSA key should be different from spending key (derived, not identical)
	assert_ne!(eddsa_key1, spending_key);
}

#[test]
fn test_eddsa_key_deterministic() {
	let spending_key = [0x42; 32];

	let key1 = derive_eddsa_key(&spending_key);
	let key2 = derive_eddsa_key(&spending_key);

	// Same spending key should always produce the same EdDSA key
	assert_eq!(key1, key2);
}

#[test]
fn test_eddsa_key_different_spending_keys() {
	let spending_key1 = [0x11; 32];
	let spending_key2 = [0x22; 32];

	let eddsa1 = derive_eddsa_key(&spending_key1);
	let eddsa2 = derive_eddsa_key(&spending_key2);

	// Different spending keys should produce different EdDSA keys
	assert_ne!(eddsa1, eddsa2);
}

#[test]
fn test_eddsa_key_from_bytes() {
	let bytes = [0x99; 32];

	let key1 = EdDSAKey::from_bytes(bytes);
	let key2 = EdDSAKey::from_bytes(bytes);

	assert_eq!(key1.as_bytes(), key2.as_bytes());
	assert_eq!(*key1.as_bytes(), bytes);
}

#[test]
fn test_key_separation_security() {
	// Security test: verify that all derived keys are different
	// and cannot be used interchangeably
	let spending_key = [0xDE; 32];
	let keyset = KeySet::from_spending_key(spending_key);

	// Collect all derived keys
	let viewing_bytes = keyset.viewing_key.as_bytes();
	let nullifier_bytes = keyset.nullifier_key.as_bytes();
	let eddsa_bytes = keyset.eddsa_key.as_bytes();

	// None should match the original spending key
	assert_ne!(viewing_bytes, &spending_key);
	assert_ne!(nullifier_bytes, &spending_key);
	assert_ne!(eddsa_bytes, &spending_key);

	// All should be unique (domain separation ensures no collisions)
	assert_ne!(viewing_bytes, nullifier_bytes);
	assert_ne!(viewing_bytes, eddsa_bytes);
	assert_ne!(nullifier_bytes, eddsa_bytes);
}
