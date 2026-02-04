//! Encrypted memo format validation utilities

use crate::domain::entities::constants::{MAX_ENCRYPTED_MEMO_SIZE, MIN_ENCRYPTED_MEMO_SIZE};

/// Validates encrypted memo format (28-104 bytes)
pub fn is_valid_encrypted_memo(data: &[u8]) -> bool {
	(MIN_ENCRYPTED_MEMO_SIZE..=MAX_ENCRYPTED_MEMO_SIZE).contains(&data.len())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::vec;

	// ===== is_valid_encrypted_memo Tests =====

	#[test]
	fn test_valid_min_size() {
		let data = vec![0u8; MIN_ENCRYPTED_MEMO_SIZE];
		assert!(is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_valid_max_size() {
		let data = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE];
		assert!(is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_valid_middle_size() {
		let size = (MIN_ENCRYPTED_MEMO_SIZE + MAX_ENCRYPTED_MEMO_SIZE) / 2;
		let data = vec![0u8; size];
		assert!(is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_invalid_too_short() {
		let data = vec![0u8; MIN_ENCRYPTED_MEMO_SIZE - 1];
		assert!(!is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_invalid_too_long() {
		let data = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE + 1];
		assert!(!is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_invalid_empty() {
		let data = vec![];
		assert!(!is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_invalid_one_byte() {
		let data = vec![0u8; 1];
		assert!(!is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_invalid_very_large() {
		let data = vec![0u8; 1000];
		assert!(!is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_boundary_just_below_min() {
		let data = vec![0u8; 27]; // MIN_ENCRYPTED_MEMO_SIZE is 28
		assert!(!is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_boundary_just_above_max() {
		let data = vec![0u8; 105]; // MAX_ENCRYPTED_MEMO_SIZE is 104
		assert!(!is_valid_encrypted_memo(&data));
	}

	#[test]
	fn test_all_valid_sizes() {
		for size in MIN_ENCRYPTED_MEMO_SIZE..=MAX_ENCRYPTED_MEMO_SIZE {
			let data = vec![0u8; size];
			assert!(
				is_valid_encrypted_memo(&data),
				"Size {size} should be valid"
			);
		}
	}

	#[test]
	fn test_sizes_below_range() {
		for size in 0..MIN_ENCRYPTED_MEMO_SIZE {
			let data = vec![0u8; size];
			assert!(
				!is_valid_encrypted_memo(&data),
				"Size {size} should be invalid (too short)"
			);
		}
	}

	#[test]
	fn test_sizes_above_range() {
		for size in (MAX_ENCRYPTED_MEMO_SIZE + 1)..=(MAX_ENCRYPTED_MEMO_SIZE + 10) {
			let data = vec![0u8; size];
			assert!(
				!is_valid_encrypted_memo(&data),
				"Size {size} should be invalid (too long)"
			);
		}
	}

	#[test]
	fn test_content_doesnt_matter() {
		// Validation only checks length, not content
		let valid_size = 50;

		let zeros = vec![0u8; valid_size];
		let ones = vec![1u8; valid_size];
		let max = vec![255u8; valid_size];
		let random = vec![42u8; valid_size];

		assert!(is_valid_encrypted_memo(&zeros));
		assert!(is_valid_encrypted_memo(&ones));
		assert!(is_valid_encrypted_memo(&max));
		assert!(is_valid_encrypted_memo(&random));
	}

	#[test]
	fn test_realistic_encrypted_memo_size() {
		// Real encrypted memo: nonce(12) + ciphertext(76) + tag(16) = 104
		let realistic_size = 104;
		let data = vec![0u8; realistic_size];

		assert!(is_valid_encrypted_memo(&data));
		assert_eq!(realistic_size, MAX_ENCRYPTED_MEMO_SIZE);
	}

	#[test]
	fn test_min_size_matches_nonce_plus_tag() {
		// Minimum should be nonce(12) + tag(16) = 28
		assert_eq!(MIN_ENCRYPTED_MEMO_SIZE, 12 + 16);
	}

	#[test]
	fn test_max_size_matches_full_format() {
		// Maximum should be nonce(12) + plaintext(76) + tag(16) = 104
		assert_eq!(MAX_ENCRYPTED_MEMO_SIZE, 12 + 76 + 16);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_validation_before_decryption() {
		// Simulate checking before attempting decryption
		let invalid_data = vec![0u8; 10];
		let valid_data = vec![0u8; 104];

		// Should reject invalid before attempting expensive decryption
		if !is_valid_encrypted_memo(&invalid_data) {
			// Skip decryption - validation passed
		} else {
			panic!("Should reject invalid data");
		}

		// Should allow valid data to proceed
		assert!(is_valid_encrypted_memo(&valid_data));
	}

	#[test]
	fn test_batch_validation() {
		let test_cases = vec![
			(vec![0u8; 0], false),   // Empty
			(vec![0u8; 10], false),  // Too short
			(vec![0u8; 28], true),   // Min valid
			(vec![0u8; 50], true),   // Middle
			(vec![0u8; 104], true),  // Max valid
			(vec![0u8; 200], false), // Too long
		];

		for (data, expected) in test_cases {
			assert_eq!(
				is_valid_encrypted_memo(&data),
				expected,
				"Failed for size {}",
				data.len()
			);
		}
	}
}
