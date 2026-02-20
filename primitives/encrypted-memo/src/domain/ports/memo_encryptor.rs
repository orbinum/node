//! Memo Encryptor port.
//!
//! Abstract interface for encrypting and decrypting note memos.
//! Implement this trait in the services layer.

use crate::domain::entities::{error::MemoError, memo_data::MemoData};

/// Port for encrypting and decrypting note memos.
pub trait MemoEncryptor {
	/// Encrypts `memo` for a recipient identified by `viewing_key`.
	///
	/// Returns `nonce(12) || ciphertext(76+16)`.
	/// The `nonce` MUST be unique per (key, commitment) pair.
	fn encrypt(
		&self,
		memo: &MemoData,
		commitment: &[u8; 32],
		viewing_key: &[u8; 32],
		nonce: &[u8; 12],
	) -> Result<alloc::vec::Vec<u8>, MemoError>;

	/// Decrypts an encrypted memo using the owner's `viewing_key`.
	fn decrypt(
		&self,
		encrypted: &[u8],
		commitment: &[u8; 32],
		viewing_key: &[u8; 32],
	) -> Result<MemoData, MemoError>;

	/// Attempts decryption returning `None` on failure.
	///
	/// Useful for blockchain scanning without propagating errors.
	fn try_decrypt(
		&self,
		encrypted: &[u8],
		commitment: &[u8; 32],
		viewing_key: &[u8; 32],
	) -> Option<MemoData> {
		self.decrypt(encrypted, commitment, viewing_key).ok()
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use crate::domain::entities::{error::MemoError, memo_data::MemoData};
	use alloc::vec::Vec;

	// Mock that always succeeds: encrypt returns raw memo bytes, decrypt parses them back.
	struct AlwaysOk;
	impl MemoEncryptor for AlwaysOk {
		fn encrypt(
			&self,
			memo: &MemoData,
			_: &[u8; 32],
			_: &[u8; 32],
			_: &[u8; 12],
		) -> Result<Vec<u8>, MemoError> {
			Ok(memo.to_bytes().to_vec())
		}

		fn decrypt(&self, data: &[u8], _: &[u8; 32], _: &[u8; 32]) -> Result<MemoData, MemoError> {
			MemoData::from_bytes(data)
		}
	}

	// Mock that always fails.
	struct AlwaysFail;
	impl MemoEncryptor for AlwaysFail {
		fn encrypt(
			&self,
			_: &MemoData,
			_: &[u8; 32],
			_: &[u8; 32],
			_: &[u8; 12],
		) -> Result<Vec<u8>, MemoError> {
			Err(MemoError::EncryptionFailed)
		}

		fn decrypt(&self, _: &[u8], _: &[u8; 32], _: &[u8; 32]) -> Result<MemoData, MemoError> {
			Err(MemoError::DecryptionFailed)
		}
	}

	fn dummy_memo() -> MemoData {
		MemoData::new(100, [1u8; 32], [2u8; 32], 0)
	}

	#[test]
	fn test_try_decrypt_returns_some_on_ok() {
		let enc = AlwaysOk;
		let memo = dummy_memo();
		let encrypted = enc
			.encrypt(&memo, &[0u8; 32], &[0u8; 32], &[0u8; 12])
			.unwrap();
		assert!(enc
			.try_decrypt(&encrypted, &[0u8; 32], &[0u8; 32])
			.is_some());
	}

	#[test]
	fn test_try_decrypt_returns_none_on_err() {
		let enc = AlwaysFail;
		assert!(enc
			.try_decrypt(&[0u8; 76], &[0u8; 32], &[0u8; 32])
			.is_none());
	}

	#[test]
	fn test_try_decrypt_returns_correct_memo() {
		let enc = AlwaysOk;
		let original = dummy_memo();
		let bytes = original.to_bytes();
		let recovered = enc.try_decrypt(&bytes, &[0u8; 32], &[0u8; 32]);
		assert_eq!(recovered, Some(original));
	}

	#[test]
	fn test_encrypt_ok_returns_bytes() {
		let enc = AlwaysOk;
		let memo = dummy_memo();
		let result = enc
			.encrypt(&memo, &[0u8; 32], &[0u8; 32], &[0u8; 12])
			.unwrap();
		assert_eq!(result, memo.to_bytes().to_vec());
	}

	#[test]
	fn test_encrypt_fail_propagates_error() {
		let enc = AlwaysFail;
		let memo = dummy_memo();
		assert_eq!(
			enc.encrypt(&memo, &[0u8; 32], &[0u8; 32], &[0u8; 12]),
			Err(MemoError::EncryptionFailed)
		);
	}

	#[test]
	fn test_decrypt_fail_propagates_error() {
		let enc = AlwaysFail;
		assert_eq!(
			enc.decrypt(&[0u8; 76], &[0u8; 32], &[0u8; 32]),
			Err(MemoError::DecryptionFailed)
		);
	}
}
