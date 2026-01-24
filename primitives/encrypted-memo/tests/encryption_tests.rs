//! Tests for encryption and decryption operations

use fp_encrypted_memo::*;

fn sample_memo() -> MemoData {
	MemoData {
		value: 1000,
		owner_pk: [1u8; 32],
		blinding: [2u8; 32],
		asset_id: 0,
	}
}

fn sample_viewing_key() -> [u8; 32] {
	[42u8; 32]
}

fn sample_commitment() -> [u8; 32] {
	[99u8; 32]
}

fn sample_nonce() -> [u8; 12] {
	[7u8; 12]
}

#[test]
fn test_memo_serialization() {
	let memo = sample_memo();
	let bytes = memo.to_bytes();

	assert_eq!(bytes.len(), 76);

	let recovered = MemoData::from_bytes(&bytes).unwrap();
	assert_eq!(recovered.value, memo.value);
	assert_eq!(recovered.owner_pk, memo.owner_pk);
	assert_eq!(recovered.blinding, memo.blinding);
	assert_eq!(recovered.asset_id, memo.asset_id);
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
	let memo = sample_memo();
	let viewing_key = sample_viewing_key();
	let commitment = sample_commitment();
	let nonce = sample_nonce();

	let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();

	// Check size
	assert_eq!(encrypted.len(), 12 + 76 + 16); // nonce + plaintext + MAC

	let decrypted = decrypt_memo(&encrypted, &commitment, &viewing_key).unwrap();

	assert_eq!(decrypted.value, memo.value);
	assert_eq!(decrypted.owner_pk, memo.owner_pk);
	assert_eq!(decrypted.blinding, memo.blinding);
	assert_eq!(decrypted.asset_id, memo.asset_id);
}

#[test]
fn test_wrong_viewing_key_fails() {
	let memo = sample_memo();
	let viewing_key = sample_viewing_key();
	let commitment = sample_commitment();
	let nonce = sample_nonce();
	let wrong_key = [99u8; 32];

	let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
	let result = decrypt_memo(&encrypted, &commitment, &wrong_key);

	assert!(result.is_err());
	assert_eq!(result.unwrap_err(), MemoError::DecryptionFailed);
}

#[test]
fn test_wrong_commitment_fails() {
	let memo = sample_memo();
	let viewing_key = sample_viewing_key();
	let commitment = sample_commitment();
	let wrong_commitment = [88u8; 32];
	let nonce = sample_nonce();

	let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
	let result = decrypt_memo(&encrypted, &wrong_commitment, &viewing_key);

	assert!(result.is_err());
}

#[test]
fn test_tampered_ciphertext_fails() {
	let memo = sample_memo();
	let viewing_key = sample_viewing_key();
	let commitment = sample_commitment();
	let nonce = sample_nonce();

	let mut encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();

	// Tamper with ciphertext
	encrypted[20] ^= 0xFF;

	let result = decrypt_memo(&encrypted, &commitment, &viewing_key);
	assert!(result.is_err());
}

#[test]
fn test_data_too_short() {
	let viewing_key = sample_viewing_key();
	let commitment = sample_commitment();

	let short_data = vec![0u8; 10];
	let result = decrypt_memo(&short_data, &commitment, &viewing_key);

	assert_eq!(result.unwrap_err(), MemoError::DataTooShort);
}

#[test]
fn test_try_decrypt_returns_none_on_failure() {
	let viewing_key = sample_viewing_key();
	let commitment = sample_commitment();
	let wrong_key = [99u8; 32];
	let nonce = sample_nonce();
	let memo = sample_memo();

	let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();

	// Try with wrong key
	let result = try_decrypt_memo(&encrypted, &commitment, &wrong_key);
	assert!(result.is_none());

	// Try with correct key
	let result = try_decrypt_memo(&encrypted, &commitment, &viewing_key);
	assert!(result.is_some());
}

#[test]
fn test_is_valid_encrypted_memo() {
	assert!(!is_valid_encrypted_memo(&[]));
	assert!(!is_valid_encrypted_memo(&[0u8; 10]));
	assert!(is_valid_encrypted_memo(&[0u8; MIN_ENCRYPTED_MEMO_SIZE]));
	assert!(is_valid_encrypted_memo(&[0u8; MAX_ENCRYPTED_MEMO_SIZE]));
	assert!(!is_valid_encrypted_memo(
		&[0u8; MAX_ENCRYPTED_MEMO_SIZE + 1]
	));
}

#[test]
fn test_large_value() {
	let memo = MemoData {
		value: u64::MAX,
		owner_pk: [0xAA; 32],
		blinding: [0xBB; 32],
		asset_id: u32::MAX,
	};

	let bytes = memo.to_bytes();
	let recovered = MemoData::from_bytes(&bytes).unwrap();

	assert_eq!(recovered.value, u64::MAX);
	assert_eq!(recovered.asset_id, u32::MAX);
}

#[cfg(feature = "encrypt")]
#[test]
fn test_encrypt_random_nonce() {
	let memo = sample_memo();
	let viewing_key = sample_viewing_key();
	let commitment = sample_commitment();

	let encrypted1 = encrypt_memo_random(&memo, &commitment, &viewing_key).unwrap();
	let encrypted2 = encrypt_memo_random(&memo, &commitment, &viewing_key).unwrap();

	// Same plaintext, different nonces -> different ciphertexts
	assert_ne!(encrypted1, encrypted2);

	// Both should decrypt correctly
	let decrypted1 = decrypt_memo(&encrypted1, &commitment, &viewing_key).unwrap();
	let decrypted2 = decrypt_memo(&encrypted2, &commitment, &viewing_key).unwrap();

	assert_eq!(decrypted1.value, memo.value);
	assert_eq!(decrypted2.value, memo.value);
}

#[test]
fn test_audit_scenario() {
	// Simulate an audit scenario where viewing key is shared
	let spending_key = [0xDE; 32];
	let keys = KeySet::from_spending_key(spending_key);

	// Owner creates encrypted memo
	let memo = MemoData {
		value: 100_000,
		owner_pk: [1u8; 32],
		blinding: [2u8; 32],
		asset_id: 0,
	};
	let commitment = [0x42; 32];
	let nonce = [0x07; 12];
	let encrypted = encrypt_memo(&memo, &commitment, keys.viewing_key.as_bytes(), &nonce).unwrap();

	// Auditor receives viewing key (not spending key!)
	let auditor_vk = keys.export_viewing_key();

	// Auditor can decrypt and see transaction details
	let audited = auditor_vk.decrypt(&encrypted, &commitment).unwrap();
	assert_eq!(audited.value, 100_000);

	// Different user's viewing key cannot decrypt
	let other_keys = KeySet::from_spending_key([0xCC; 32]);
	let result = other_keys.viewing_key.try_decrypt(&encrypted, &commitment);
	assert!(result.is_none());
}
