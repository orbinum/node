//! Tests for KeySet management

use fp_encrypted_memo::*;

fn sample_spending_key() -> [u8; 32] {
	[0xDE; 32]
}

fn sample_memo() -> MemoData {
	MemoData {
		value: 1000,
		owner_pk: [1u8; 32],
		blinding: [2u8; 32],
		asset_id: 0,
	}
}

fn sample_commitment() -> [u8; 32] {
	[99u8; 32]
}

fn sample_nonce() -> [u8; 12] {
	[7u8; 12]
}

#[test]
fn test_keyset_derivation() {
	let spending_key = sample_spending_key();
	let keys = KeySet::from_spending_key(spending_key);

	// All keys should be different
	assert_ne!(keys.spending_key, *keys.viewing_key.as_bytes());
	assert_ne!(keys.spending_key, *keys.nullifier_key.as_bytes());
	assert_ne!(keys.viewing_key.as_bytes(), keys.nullifier_key.as_bytes());
}

#[test]
fn test_keyset_export_viewing_key() {
	let spending_key = sample_spending_key();
	let keys = KeySet::from_spending_key(spending_key);

	let exported = keys.export_viewing_key();
	assert_eq!(exported, keys.viewing_key);
	assert!(keys.matches_viewing_key(&exported));
}

#[test]
fn test_viewing_key_decrypt() {
	let spending_key = sample_spending_key();
	let keys = KeySet::from_spending_key(spending_key);

	let memo = sample_memo();
	let commitment = sample_commitment();
	let nonce = sample_nonce();

	// Encrypt with viewing key
	let encrypted = encrypt_memo(&memo, &commitment, keys.viewing_key.as_bytes(), &nonce).unwrap();

	// Decrypt using ViewingKey method
	let decrypted = keys.viewing_key.decrypt(&encrypted, &commitment).unwrap();
	assert_eq!(decrypted.value, memo.value);
}

#[test]
fn test_viewing_key_try_decrypt() {
	let spending_key = sample_spending_key();
	let keys = KeySet::from_spending_key(spending_key);

	let memo = sample_memo();
	let commitment = sample_commitment();
	let nonce = sample_nonce();

	// Encrypt with viewing key
	let encrypted = encrypt_memo(&memo, &commitment, keys.viewing_key.as_bytes(), &nonce).unwrap();

	// Try decrypt with correct key
	let result = keys.viewing_key.try_decrypt(&encrypted, &commitment);
	assert!(result.is_some());

	// Try decrypt with wrong key
	let wrong_keys = KeySet::from_spending_key([0xFF; 32]);
	let result = wrong_keys.viewing_key.try_decrypt(&encrypted, &commitment);
	assert!(result.is_none());
}

#[test]
fn test_keyset_includes_eddsa_key() {
	let spending_key = [0x55; 32];
	let keyset = KeySet::from_spending_key(spending_key);

	// All derived keys should be different from each other
	assert_ne!(
		keyset.viewing_key.as_bytes(),
		keyset.nullifier_key.as_bytes()
	);
	assert_ne!(keyset.viewing_key.as_bytes(), keyset.eddsa_key.as_bytes());
	assert_ne!(keyset.nullifier_key.as_bytes(), keyset.eddsa_key.as_bytes());

	// EdDSA key in keyset should match convenience function
	let expected_eddsa = derive_eddsa_key(&spending_key);
	assert_eq!(*keyset.eddsa_key.as_bytes(), expected_eddsa);
}
