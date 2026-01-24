//! Validation utilities for encrypted memos

use crate::core::constants::{MAX_ENCRYPTED_MEMO_SIZE, MIN_ENCRYPTED_MEMO_SIZE};

/// Check if encrypted data has valid format (without decrypting)
///
/// Validates that the data length is within acceptable bounds:
/// - Minimum: 12 (nonce) + 16 (MAC) = 28 bytes
/// - Maximum: 12 (nonce) + 76 (data) + 16 (MAC) = 104 bytes
pub fn is_valid_encrypted_memo(data: &[u8]) -> bool {
	(MIN_ENCRYPTED_MEMO_SIZE..=MAX_ENCRYPTED_MEMO_SIZE).contains(&data.len())
}

/// Validate memo size is within bounds
///
/// Returns `true` if size is valid, `false` otherwise.
pub fn validate_memo_size(size: usize) -> bool {
	(MIN_ENCRYPTED_MEMO_SIZE..=MAX_ENCRYPTED_MEMO_SIZE).contains(&size)
}
