//! Encryption Service
//!
//! ChaCha20Poly1305 AEAD encryption/decryption for memo data.

use alloc::vec::Vec;
use chacha20poly1305::{
	aead::{Aead, KeyInit},
	ChaCha20Poly1305, Nonce,
};

use crate::domain::entities::{
	constants::{MAX_ENCRYPTED_MEMO_SIZE, MIN_ENCRYPTED_MEMO_SIZE},
	error::MemoError,
	types::MemoData,
};
use crate::domain::services::key_derivation::derive_encryption_key;

/// Decrypts encrypted memo using viewing key
///
/// Format: nonce(12) || ciphertext. Returns MemoData or error.
pub fn decrypt_memo(
	encrypted: &[u8],
	commitment: &[u8; 32],
	viewing_key: &[u8; 32],
) -> Result<MemoData, MemoError> {
	// Validate length
	if encrypted.len() < MIN_ENCRYPTED_MEMO_SIZE {
		return Err(MemoError::DataTooShort);
	}
	if encrypted.len() > MAX_ENCRYPTED_MEMO_SIZE {
		return Err(MemoError::DataTooLong);
	}

	// Extract nonce and ciphertext
	let (nonce_bytes, ciphertext) = encrypted.split_at(12);
	let nonce = Nonce::from_slice(nonce_bytes);

	// Derive decryption key
	let key = derive_encryption_key(viewing_key, commitment);

	// Create cipher and decrypt
	let cipher = ChaCha20Poly1305::new((&key).into());
	let plaintext = cipher
		.decrypt(nonce, ciphertext)
		.map_err(|_| MemoError::DecryptionFailed)?;

	// Parse memo data
	MemoData::from_bytes(&plaintext)
}

/// Encrypts memo data with provided nonce
///
/// Returns: nonce(12) || ciphertext(76+16)
/// WARNING: Nonce MUST be unique and never reused.
pub fn encrypt_memo(
	memo: &MemoData,
	commitment: &[u8; 32],
	recipient_viewing_key: &[u8; 32],
	nonce: &[u8; 12],
) -> Result<Vec<u8>, MemoError> {
	// Derive encryption key
	let key = derive_encryption_key(recipient_viewing_key, commitment);

	// Serialize memo data
	let plaintext = memo.to_bytes();

	// Create cipher and encrypt
	let cipher = ChaCha20Poly1305::new((&key).into());
	let nonce_obj = Nonce::from_slice(nonce);
	let ciphertext = cipher
		.encrypt(nonce_obj, plaintext.as_ref())
		.map_err(|_| MemoError::EncryptionFailed)?;

	// Return nonce || ciphertext
	let mut result = Vec::with_capacity(12 + ciphertext.len());
	result.extend_from_slice(nonce);
	result.extend_from_slice(&ciphertext);

	Ok(result)
}

/// Encrypts memo with auto-generated random nonce
///
/// Recommended method. Requires encrypt feature.
#[cfg(feature = "encrypt")]
pub fn encrypt_memo_random(
	memo: &MemoData,
	commitment: &[u8; 32],
	recipient_viewing_key: &[u8; 32],
) -> Result<Vec<u8>, MemoError> {
	use rand::RngCore;

	let mut nonce = [0u8; 12];
	rand::thread_rng().fill_bytes(&mut nonce);

	encrypt_memo(memo, commitment, recipient_viewing_key, &nonce)
}

/// Attempts decryption, returns None on failure
///
/// Useful for scanning blockchain to find owned notes.
pub fn try_decrypt_memo(
	encrypted: &[u8],
	commitment: &[u8; 32],
	viewing_key: &[u8; 32],
) -> Option<MemoData> {
	decrypt_memo(encrypted, commitment, viewing_key).ok()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::vec;

	// ===== encrypt_memo Tests =====

	#[test]
	fn test_encrypt_memo_basic() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let nonce = [5u8; 12];

		let result = encrypt_memo(&memo, &commitment, &viewing_key, &nonce);

		assert!(result.is_ok());
		let encrypted = result.unwrap();
		assert!(encrypted.len() >= MIN_ENCRYPTED_MEMO_SIZE);
		assert!(encrypted.len() <= MAX_ENCRYPTED_MEMO_SIZE);
	}

	#[test]
	fn test_encrypt_memo_nonce_included() {
		let memo = MemoData::new(500, [10u8; 32], [20u8; 32], 1);
		let commitment = [30u8; 32];
		let viewing_key = [40u8; 32];
		let nonce = [99u8; 12];

		let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();

		// First 12 bytes should be nonce
		assert_eq!(&encrypted[0..12], &nonce);
	}

	#[test]
	fn test_encrypt_memo_deterministic_with_same_nonce() {
		let memo = MemoData::new(100, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let nonce = [5u8; 12];

		let encrypted1 = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
		let encrypted2 = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();

		// Same inputs should produce same output
		assert_eq!(encrypted1, encrypted2);
	}

	#[test]
	fn test_encrypt_memo_different_nonces() {
		let memo = MemoData::new(100, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let nonce1 = [5u8; 12];
		let nonce2 = [6u8; 12];

		let encrypted1 = encrypt_memo(&memo, &commitment, &viewing_key, &nonce1).unwrap();
		let encrypted2 = encrypt_memo(&memo, &commitment, &viewing_key, &nonce2).unwrap();

		// Different nonces should produce different ciphertexts
		assert_ne!(encrypted1, encrypted2);
	}

	#[test]
	fn test_encrypt_memo_zero_value() {
		let memo = MemoData::new(0, [0u8; 32], [0u8; 32], 0);
		let commitment = [0u8; 32];
		let viewing_key = [0u8; 32];
		let nonce = [0u8; 12];

		let result = encrypt_memo(&memo, &commitment, &viewing_key, &nonce);
		assert!(result.is_ok());
	}

	#[test]
	fn test_encrypt_memo_max_value() {
		let memo = MemoData::new(u64::MAX, [255u8; 32], [255u8; 32], u32::MAX);
		let commitment = [255u8; 32];
		let viewing_key = [255u8; 32];
		let nonce = [255u8; 12];

		let result = encrypt_memo(&memo, &commitment, &viewing_key, &nonce);
		assert!(result.is_ok());
	}

	// ===== decrypt_memo Tests =====

	#[test]
	fn test_decrypt_memo_basic() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let nonce = [5u8; 12];

		let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
		let decrypted = decrypt_memo(&encrypted, &commitment, &viewing_key).unwrap();

		assert_eq!(decrypted, memo);
	}

	#[test]
	fn test_decrypt_memo_roundtrip() {
		let original = MemoData::new(500, [10u8; 32], [20u8; 32], 1);
		let commitment = [30u8; 32];
		let viewing_key = [40u8; 32];
		let nonce = [50u8; 12];

		let encrypted = encrypt_memo(&original, &commitment, &viewing_key, &nonce).unwrap();
		let decrypted = decrypt_memo(&encrypted, &commitment, &viewing_key).unwrap();

		assert_eq!(decrypted.value, original.value);
		assert_eq!(decrypted.owner_pk, original.owner_pk);
		assert_eq!(decrypted.blinding, original.blinding);
		assert_eq!(decrypted.asset_id, original.asset_id);
	}

	#[test]
	fn test_decrypt_memo_wrong_key() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let wrong_key = [99u8; 32];
		let nonce = [5u8; 12];

		let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
		let result = decrypt_memo(&encrypted, &commitment, &wrong_key);

		assert!(result.is_err());
		if let Err(MemoError::DecryptionFailed) = result {
			// Expected
		} else {
			panic!("Expected DecryptionFailed error");
		}
	}

	#[test]
	fn test_decrypt_memo_wrong_commitment() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let wrong_commitment = [99u8; 32];
		let viewing_key = [4u8; 32];
		let nonce = [5u8; 12];

		let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
		let result = decrypt_memo(&encrypted, &wrong_commitment, &viewing_key);

		assert!(result.is_err());
	}

	#[test]
	fn test_decrypt_memo_too_short() {
		let encrypted = vec![0u8; MIN_ENCRYPTED_MEMO_SIZE - 1];
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];

		let result = decrypt_memo(&encrypted, &commitment, &viewing_key);

		assert!(result.is_err());
		if let Err(MemoError::DataTooShort) = result {
			// Expected
		} else {
			panic!("Expected DataTooShort error");
		}
	}

	#[test]
	fn test_decrypt_memo_too_long() {
		let encrypted = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE + 1];
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];

		let result = decrypt_memo(&encrypted, &commitment, &viewing_key);

		assert!(result.is_err());
		if let Err(MemoError::DataTooLong) = result {
			// Expected
		} else {
			panic!("Expected DataTooLong error");
		}
	}

	#[test]
	fn test_decrypt_memo_tampered_ciphertext() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let nonce = [5u8; 12];

		let mut encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
		// Tamper with ciphertext
		encrypted[20] ^= 0xFF;

		let result = decrypt_memo(&encrypted, &commitment, &viewing_key);
		assert!(result.is_err());
	}

	// ===== encrypt_memo_random Tests =====

	#[cfg(feature = "encrypt")]
	#[test]
	fn test_encrypt_memo_random() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];

		let result = encrypt_memo_random(&memo, &commitment, &viewing_key);

		assert!(result.is_ok());
		let encrypted = result.unwrap();
		assert!(encrypted.len() >= MIN_ENCRYPTED_MEMO_SIZE);
	}

	#[cfg(feature = "encrypt")]
	#[test]
	fn test_encrypt_memo_random_different_nonces() {
		let memo = MemoData::new(100, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];

		let encrypted1 = encrypt_memo_random(&memo, &commitment, &viewing_key).unwrap();
		let encrypted2 = encrypt_memo_random(&memo, &commitment, &viewing_key).unwrap();

		// Should have different nonces (first 12 bytes)
		assert_ne!(&encrypted1[0..12], &encrypted2[0..12]);
	}

	#[cfg(feature = "encrypt")]
	#[test]
	fn test_encrypt_memo_random_roundtrip() {
		let original = MemoData::new(500, [10u8; 32], [20u8; 32], 1);
		let commitment = [30u8; 32];
		let viewing_key = [40u8; 32];

		let encrypted = encrypt_memo_random(&original, &commitment, &viewing_key).unwrap();
		let decrypted = decrypt_memo(&encrypted, &commitment, &viewing_key).unwrap();

		assert_eq!(decrypted, original);
	}

	// ===== try_decrypt_memo Tests =====

	#[test]
	fn test_try_decrypt_memo_success() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let nonce = [5u8; 12];

		let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
		let result = try_decrypt_memo(&encrypted, &commitment, &viewing_key);

		assert!(result.is_some());
		assert_eq!(result.unwrap(), memo);
	}

	#[test]
	fn test_try_decrypt_memo_failure() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let wrong_key = [99u8; 32];
		let nonce = [5u8; 12];

		let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();
		let result = try_decrypt_memo(&encrypted, &commitment, &wrong_key);

		assert!(result.is_none());
	}

	#[test]
	fn test_try_decrypt_memo_invalid_data() {
		let encrypted = vec![0u8; 10]; // Too short
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];

		let result = try_decrypt_memo(&encrypted, &commitment, &viewing_key);
		assert!(result.is_none());
	}

	// ===== Integration Tests =====

	#[test]
	fn test_multiple_memos_different_keys() {
		let memo1 = MemoData::new(100, [1u8; 32], [2u8; 32], 0);
		let memo2 = MemoData::new(200, [3u8; 32], [4u8; 32], 1);
		let commitment = [5u8; 32];
		let vk1 = [6u8; 32];
		let vk2 = [7u8; 32];
		let nonce1 = [8u8; 12];
		let nonce2 = [9u8; 12];

		let encrypted1 = encrypt_memo(&memo1, &commitment, &vk1, &nonce1).unwrap();
		let encrypted2 = encrypt_memo(&memo2, &commitment, &vk2, &nonce2).unwrap();

		// Each key can only decrypt its own memo
		assert_eq!(decrypt_memo(&encrypted1, &commitment, &vk1).unwrap(), memo1);
		assert_eq!(decrypt_memo(&encrypted2, &commitment, &vk2).unwrap(), memo2);
		assert!(decrypt_memo(&encrypted1, &commitment, &vk2).is_err());
		assert!(decrypt_memo(&encrypted2, &commitment, &vk1).is_err());
	}

	#[test]
	fn test_encryption_size_consistency() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let commitment = [3u8; 32];
		let viewing_key = [4u8; 32];
		let nonce = [5u8; 12];

		let encrypted = encrypt_memo(&memo, &commitment, &viewing_key, &nonce).unwrap();

		// Should be: 12 (nonce) + 76 (plaintext) + 16 (auth tag) = 104 bytes
		assert_eq!(encrypted.len(), 12 + 76 + 16);
	}

	#[test]
	fn test_various_memo_values() {
		let test_cases = vec![
			MemoData::new(0, [0u8; 32], [0u8; 32], 0),
			MemoData::new(1, [1u8; 32], [1u8; 32], 1),
			MemoData::new(1000, [10u8; 32], [20u8; 32], 5),
			MemoData::new(u64::MAX, [255u8; 32], [128u8; 32], u32::MAX),
		];

		let commitment = [42u8; 32];
		let viewing_key = [99u8; 32];
		let nonce = [7u8; 12];

		for original in test_cases {
			let encrypted = encrypt_memo(&original, &commitment, &viewing_key, &nonce).unwrap();
			let decrypted = decrypt_memo(&encrypted, &commitment, &viewing_key).unwrap();
			assert_eq!(decrypted, original);
		}
	}

	#[test]
	fn test_blockchain_scanning_simulation() {
		// Simulate scanning blockchain for owned notes
		let wallet_vk = [42u8; 32];
		let other_vk = [99u8; 32];
		let commitment = [10u8; 32];

		// Create memos for different recipients
		let owned_memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let other_memo = MemoData::new(500, [3u8; 32], [4u8; 32], 0);

		let owned_encrypted =
			encrypt_memo(&owned_memo, &commitment, &wallet_vk, &[1u8; 12]).unwrap();
		let other_encrypted =
			encrypt_memo(&other_memo, &commitment, &other_vk, &[2u8; 12]).unwrap();

		// Wallet can only decrypt owned notes
		assert!(try_decrypt_memo(&owned_encrypted, &commitment, &wallet_vk).is_some());
		assert!(try_decrypt_memo(&other_encrypted, &commitment, &wallet_vk).is_none());
	}
}
