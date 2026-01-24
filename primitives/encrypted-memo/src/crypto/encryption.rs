//! ChaCha20Poly1305 encryption and decryption for memos

use alloc::vec::Vec;
use chacha20poly1305::{
	aead::{Aead, KeyInit},
	ChaCha20Poly1305, Nonce,
};

use crate::core::{
	constants::{MAX_ENCRYPTED_MEMO_SIZE, MIN_ENCRYPTED_MEMO_SIZE},
	error::MemoError,
	types::MemoData,
};
use crate::crypto::key_derivation::derive_encryption_key;

/// Decrypt an encrypted memo
///
/// # Arguments
///
/// * `encrypted` - The encrypted memo (nonce || ciphertext)
/// * `commitment` - The note commitment (used for key derivation)
/// * `viewing_key` - The recipient's viewing key
///
/// # Returns
///
/// * `Ok(MemoData)` - Successfully decrypted memo data
/// * `Err(MemoError)` - Decryption failed (wrong key or tampered)
///
/// # Example
///
/// ```rust,ignore
/// let memo = decrypt_memo(&encrypted, &commitment, &viewing_key)?;
/// println!("Received {} tokens", memo.value);
/// ```
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

/// Encrypt memo data for a recipient
///
/// # Arguments
///
/// * `memo` - The plaintext memo data
/// * `commitment` - The note commitment (used for key derivation)
/// * `recipient_viewing_key` - The recipient's viewing key
/// * `nonce` - 12-byte random nonce (MUST be unique per encryption)
///
/// # Returns
///
/// Encrypted memo bytes: nonce (12) || ciphertext (76 + 16 MAC)
///
/// # Security Warning
///
/// The nonce MUST be randomly generated and NEVER reused with the same key.
/// Nonce reuse allows an attacker to recover plaintext.
///
/// # Example
///
/// ```rust,ignore
/// let mut nonce = [0u8; 12];
/// rand::thread_rng().fill_bytes(&mut nonce);
/// let encrypted = encrypt_memo(&memo, &commitment, &recipient_vk, &nonce)?;
/// ```
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

/// Encrypt memo with random nonce (requires `encrypt` feature)
///
/// This is the recommended way to encrypt memos as it automatically
/// generates a cryptographically secure random nonce.
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

/// Try to decrypt a memo - returns None if decryption fails
///
/// This is useful for scanning blockchain events to find owned notes.
/// A failed decryption simply means the note doesn't belong to this wallet.
pub fn try_decrypt_memo(
	encrypted: &[u8],
	commitment: &[u8; 32],
	viewing_key: &[u8; 32],
) -> Option<MemoData> {
	decrypt_memo(encrypted, commitment, viewing_key).ok()
}
