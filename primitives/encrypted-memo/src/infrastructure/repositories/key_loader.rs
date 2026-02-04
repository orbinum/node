//! Proving key validation, format detection, and checksum verification

use crate::domain::entities::error::MemoError;

// ============================================================================
// Proving Key Validation (Core Responsibility)
// ============================================================================

/// Validates proving key format (size, entropy, non-zero data)
pub fn validate_proving_key(key_bytes: &[u8]) -> Result<(), MemoError> {
	// Basic size validation
	if key_bytes.len() < 10_000 {
		return Err(MemoError::InvalidProvingKey(
			"Proving key too small (< 10KB), likely corrupted or incomplete",
		));
	}

	if key_bytes.len() > 10_000_000 {
		return Err(MemoError::InvalidProvingKey(
			"Proving key too large (> 10MB), unexpected size",
		));
	}

	// For .ark format, the first bytes should be valid
	// ark-serialize uses compressed serialization
	// We cannot fully deserialize without importing ProvingKey here,
	// but we can do basic checks

	// Check: There should be non-zero data
	let non_zero = key_bytes.iter().any(|&b| b != 0);
	if !non_zero {
		return Err(MemoError::InvalidProvingKey(
			"Proving key is all zeros, likely corrupted",
		));
	}

	// Check: Reasonable entropy (should not be repeated data)
	let first_byte = key_bytes[0];
	let all_same = key_bytes.iter().all(|&b| b == first_byte);
	if all_same {
		return Err(MemoError::InvalidProvingKey(
			"Proving key has no entropy, likely corrupted or placeholder",
		));
	}

	Ok(())
}

// ============================================================================
// Advanced Utilities
// ============================================================================

/// Calculates SHA-256 checksum for integrity verification
#[cfg(feature = "std")]
pub fn calculate_key_checksum(key_bytes: &[u8]) -> alloc::string::String {
	use sha2::{Digest, Sha256};
	let hash = Sha256::digest(key_bytes);
	hex::encode(hash)
}
/// Displays formatted proving key information
#[cfg(feature = "std")]
pub fn print_key_info(key_bytes: &[u8], label: &str) {
	println!("\n=== {} ===", label);
	println!(
		"  Size: {} KB ({} bytes)",
		key_bytes.len() / 1024,
		key_bytes.len()
	);
	println!("  Format: {}", detect_key_format(key_bytes));
	println!("  SHA-256: {}", calculate_key_checksum(key_bytes));

	// Check validation
	match validate_proving_key(key_bytes) {
		Ok(()) => println!("  Validation: ✅ PASS"),
		Err(e) => println!("  Validation: ❌ FAIL ({e})"),
	}
}

/// Verifies SHA-256 checksum matches expected value
#[cfg(feature = "std")]
pub fn verify_key_checksum(key_bytes: &[u8], expected_checksum: &str) -> Result<(), MemoError> {
	let actual = calculate_key_checksum(key_bytes);

	if actual.to_lowercase() == expected_checksum.to_lowercase() {
		Ok(())
	} else {
		Err(MemoError::InvalidProvingKey(
			alloc::format!("Checksum mismatch. Expected: {expected_checksum}, Got: {actual}")
				.leak(),
		))
	}
}

// ============================================================================
// Format Detection (No I/O)
// ============================================================================

/// Detects key format: "ark", "zkey", or "unknown"
pub fn detect_key_format(bytes: &[u8]) -> &'static str {
	// .zkey format has "zkey" magic bytes at start
	if bytes.len() > 4 && &bytes[0..4] == b"zkey" {
		return "zkey";
	}

	// .ark format (ark-serialize) doesn't have magic bytes,
	// but typically starts with compressed encoding
	if bytes.len() > 100 {
		return "ark";
	}

	"unknown"
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// ===== validate_proving_key Tests =====

	#[test]
	fn test_validate_proving_key_valid() {
		// Valid key: 50KB of varied data
		let key = (0..50000).map(|i| (i % 256) as u8).collect::<Vec<_>>();
		assert!(validate_proving_key(&key).is_ok());
	}

	#[test]
	fn test_validate_proving_key_too_small() {
		let key = vec![1u8; 5000]; // < 10KB
		let result = validate_proving_key(&key);

		assert!(result.is_err());
		if let Err(MemoError::InvalidProvingKey(msg)) = result {
			assert!(msg.contains("too small"));
		} else {
			panic!("Expected InvalidProvingKey error");
		}
	}

	#[test]
	fn test_validate_proving_key_too_large() {
		let key = vec![1u8; 11_000_000]; // > 10MB
		let result = validate_proving_key(&key);

		assert!(result.is_err());
		if let Err(MemoError::InvalidProvingKey(msg)) = result {
			assert!(msg.contains("too large"));
		} else {
			panic!("Expected InvalidProvingKey error");
		}
	}

	#[test]
	fn test_validate_proving_key_all_zeros() {
		let key = vec![0u8; 50000];
		let result = validate_proving_key(&key);

		assert!(result.is_err());
		if let Err(MemoError::InvalidProvingKey(msg)) = result {
			assert!(msg.contains("all zeros"));
		} else {
			panic!("Expected InvalidProvingKey error");
		}
	}

	#[test]
	fn test_validate_proving_key_no_entropy() {
		let key = vec![42u8; 50000]; // All same byte
		let result = validate_proving_key(&key);

		assert!(result.is_err());
		if let Err(MemoError::InvalidProvingKey(msg)) = result {
			assert!(msg.contains("no entropy"));
		} else {
			panic!("Expected InvalidProvingKey error");
		}
	}

	#[test]
	fn test_validate_proving_key_min_valid_size() {
		// Exactly 10KB with varied data
		let key = (0..10000).map(|i| (i % 256) as u8).collect::<Vec<_>>();
		assert!(validate_proving_key(&key).is_ok());
	}

	#[test]
	fn test_validate_proving_key_max_valid_size() {
		// Exactly 10MB with varied data
		let key = (0..10_000_000).map(|i| (i % 256) as u8).collect::<Vec<_>>();
		assert!(validate_proving_key(&key).is_ok());
	}

	#[test]
	fn test_validate_proving_key_realistic() {
		// Realistic key: 1MB with pseudo-random data
		let mut key = Vec::with_capacity(1_000_000);
		for i in 0..1_000_000 {
			key.push(((i * 7 + 13) % 256) as u8);
		}
		assert!(validate_proving_key(&key).is_ok());
	}

	// ===== detect_key_format Tests =====

	#[test]
	fn test_detect_key_format_zkey() {
		let mut bytes = vec![0u8; 200];
		bytes[0..4].copy_from_slice(b"zkey");

		assert_eq!(detect_key_format(&bytes), "zkey");
	}

	#[test]
	fn test_detect_key_format_ark() {
		let bytes = vec![1, 2, 3, 4, 5]; // Not "zkey", more than 100 bytes
		let mut ark_bytes = bytes;
		ark_bytes.extend(vec![0u8; 200]);

		assert_eq!(detect_key_format(&ark_bytes), "ark");
	}

	#[test]
	fn test_detect_key_format_unknown_too_small() {
		let bytes = vec![1, 2, 3]; // < 100 bytes, not "zkey"
		assert_eq!(detect_key_format(&bytes), "unknown");
	}

	#[test]
	fn test_detect_key_format_unknown_empty() {
		let bytes = vec![];
		assert_eq!(detect_key_format(&bytes), "unknown");
	}

	#[test]
	fn test_detect_key_format_zkey_exact() {
		// Real zkey format starts with "zkey" magic bytes
		let mut bytes = b"zkey".to_vec();
		bytes.extend(vec![1, 2, 3, 4, 5]);
		assert_eq!(detect_key_format(&bytes), "zkey");
	}

	#[test]
	fn test_detect_key_format_zkey_with_data() {
		// Realistic zkey header with version and section info
		let mut bytes = vec![0x7a, 0x6b, 0x65, 0x79]; // "zkey" in hex
		bytes.extend(vec![0x01, 0x00, 0x00, 0x00]); // version
		bytes.extend(vec![0u8; 100]);
		assert_eq!(detect_key_format(&bytes), "zkey");
	}

	#[test]
	fn test_detect_key_format_not_zkey_prefix() {
		let bytes = b"xkey".to_vec(); // Similar but not "zkey"
		assert_eq!(detect_key_format(&bytes), "unknown");
	}

	#[test]
	fn test_detect_key_format_ark_realistic() {
		// Real ark-serialize format (no magic bytes, binary data)
		let bytes = vec![
			0xe2, 0xf2, 0x6d, 0xbe, 0xa2, 0x99, 0xf5, 0x22, 0x3b, 0x64, 0x6c, 0xb1, 0xfb, 0x33,
			0xea, 0xdb,
		];
		let mut ark_bytes = bytes;
		ark_bytes.extend(vec![0u8; 200]);
		assert_eq!(detect_key_format(&ark_bytes), "ark");
	}

	// ===== calculate_key_checksum Tests (requires std feature) =====

	#[cfg(feature = "std")]
	#[test]
	fn test_calculate_key_checksum_basic() {
		let key = vec![1, 2, 3, 4, 5];
		let checksum = calculate_key_checksum(&key);

		// SHA-256 produces 64 hex characters
		assert_eq!(checksum.len(), 64);
		assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_calculate_key_checksum_deterministic() {
		let key = vec![10, 20, 30, 40, 50];

		let checksum1 = calculate_key_checksum(&key);
		let checksum2 = calculate_key_checksum(&key);

		assert_eq!(checksum1, checksum2);
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_calculate_key_checksum_different_data() {
		let key1 = vec![1, 2, 3];
		let key2 = vec![4, 5, 6];

		let checksum1 = calculate_key_checksum(&key1);
		let checksum2 = calculate_key_checksum(&key2);

		assert_ne!(checksum1, checksum2);
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_calculate_key_checksum_empty() {
		let key = vec![];
		let checksum = calculate_key_checksum(&key);

		// SHA-256 of empty input is known value
		assert_eq!(
			checksum,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		);
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_calculate_key_checksum_lowercase() {
		let key = vec![255, 255, 255];
		let checksum = calculate_key_checksum(&key);

		// Should be lowercase hex
		assert!(checksum.chars().all(|c| !c.is_ascii_uppercase()));
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_calculate_key_checksum_large_key() {
		let key = vec![42u8; 1_000_000];
		let checksum = calculate_key_checksum(&key);

		assert_eq!(checksum.len(), 64);
	}

	// ===== verify_key_checksum Tests (requires std feature) =====

	#[cfg(feature = "std")]
	#[test]
	fn test_verify_key_checksum_valid() {
		let key = vec![1, 2, 3, 4, 5];
		let checksum = calculate_key_checksum(&key);

		assert!(verify_key_checksum(&key, &checksum).is_ok());
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_verify_key_checksum_invalid() {
		let key = vec![1, 2, 3, 4, 5];
		let wrong_checksum = "0000000000000000000000000000000000000000000000000000000000000000";

		let result = verify_key_checksum(&key, wrong_checksum);
		assert!(result.is_err());
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_verify_key_checksum_case_insensitive() {
		let key = vec![10, 20, 30];
		let checksum_lower = calculate_key_checksum(&key);
		let checksum_upper = checksum_lower.to_uppercase();

		// Both should work
		assert!(verify_key_checksum(&key, &checksum_lower).is_ok());
		assert!(verify_key_checksum(&key, &checksum_upper).is_ok());
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_verify_key_checksum_mismatch_error_message() {
		let key = vec![5, 4, 3, 2, 1];
		let wrong = "abcd1234";

		let result = verify_key_checksum(&key, wrong);
		assert!(result.is_err());

		if let Err(MemoError::InvalidProvingKey(msg)) = result {
			assert!(msg.contains("Checksum mismatch"));
			assert!(msg.contains("Expected"));
			assert!(msg.contains("Got"));
		} else {
			panic!("Expected InvalidProvingKey with checksum mismatch");
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_verify_key_checksum_empty_key() {
		let key = vec![];
		let checksum = calculate_key_checksum(&key);

		assert!(verify_key_checksum(&key, &checksum).is_ok());
	}

	// ===== Integration Tests =====

	#[test]
	fn test_full_validation_pipeline() {
		// Create valid key
		let key = (0..50000).map(|i| (i % 256) as u8).collect::<Vec<_>>();

		// Validate
		assert!(validate_proving_key(&key).is_ok());

		// Detect format
		let format = detect_key_format(&key);
		assert_eq!(format, "ark");
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_checksum_validation_pipeline() {
		let key = vec![7, 8, 9, 10, 11];

		// Calculate checksum
		let checksum = calculate_key_checksum(&key);

		// Verify checksum
		assert!(verify_key_checksum(&key, &checksum).is_ok());

		// Modify key slightly
		let mut modified_key = key.clone();
		modified_key[0] ^= 1;

		// Checksum should fail
		assert!(verify_key_checksum(&modified_key, &checksum).is_err());
	}

	#[test]
	fn test_format_detection_all_types() {
		// zkey format
		let mut zkey = vec![0u8; 200];
		zkey[0..4].copy_from_slice(b"zkey");
		assert_eq!(detect_key_format(&zkey), "zkey");

		// ark format
		let ark = vec![1u8; 200];
		assert_eq!(detect_key_format(&ark), "ark");

		// unknown format
		let unknown = vec![2u8; 50];
		assert_eq!(detect_key_format(&unknown), "unknown");
	}

	#[test]
	fn test_validation_rejects_corrupted_keys() {
		let test_cases = vec![
			(vec![0u8; 5000], "too small"),       // Too small
			(vec![0u8; 50000], "all zeros"),      // All zeros
			(vec![99u8; 50000], "no entropy"),    // No entropy
			(vec![1u8; 11_000_000], "too large"), // Too large
		];

		for (key, _expected_error) in test_cases {
			assert!(validate_proving_key(&key).is_err());
		}
	}

	#[test]
	fn test_validation_accepts_good_keys() {
		let test_cases = vec![
			(0..10000).map(|i| (i % 256) as u8).collect::<Vec<_>>(), // Min size
			(0..100000).map(|i| (i % 256) as u8).collect::<Vec<_>>(), // Medium
			(0..1_000_000).map(|i| (i % 256) as u8).collect::<Vec<_>>(), // Large
		];

		for key in test_cases {
			assert!(validate_proving_key(&key).is_ok());
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_checksum_changes_with_single_bit() {
		let key1 = vec![0b00000000u8; 100];
		let key2 = vec![0b00000001u8; 100];

		let checksum1 = calculate_key_checksum(&key1);
		let checksum2 = calculate_key_checksum(&key2);

		// Single bit difference should produce completely different checksum
		assert_ne!(checksum1, checksum2);
	}

	#[test]
	fn test_entropy_check_boundary() {
		// Key with only two different bytes should still pass
		let mut key = vec![1u8; 50000];
		key[1000] = 2; // Change one byte

		assert!(validate_proving_key(&key).is_ok());
	}
}
