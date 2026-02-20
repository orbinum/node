//! Constants
//!
//! Size constraints and domain separators for all encrypted memo operations.

// ============================================================================
// Size constants
// ============================================================================

/// Maximum encrypted memo size in bytes.
///
/// Layout: `nonce(12) + note_data(76) + MAC(16) = 104`
pub const MAX_ENCRYPTED_MEMO_SIZE: usize = 104;

/// Minimum encrypted memo size in bytes.
///
/// Layout: `nonce(12) + MAC(16) = 28`
pub const MIN_ENCRYPTED_MEMO_SIZE: usize = 12 + 16;

/// Plaintext memo data size (before encryption)
pub const MEMO_DATA_SIZE: usize = 76;

/// Size of ChaCha20Poly1305 nonce in bytes
pub const NONCE_SIZE: usize = 12;

/// Size of ChaCha20Poly1305 authentication tag in bytes
pub const MAC_SIZE: usize = 16;

// ============================================================================
// Domain separators
// ============================================================================

/// Domain separator for per-note encryption key derivation
pub const KEY_DOMAIN: &[u8] = b"orbinum-note-encryption-v1";

/// Domain separator for viewing key derivation
pub const VIEWING_KEY_DOMAIN: &[u8] = b"orbinum-viewing-key-v1";

/// Domain separator for nullifier key derivation
pub const NULLIFIER_KEY_DOMAIN: &[u8] = b"orbinum-nullifier-key-v1";

/// Domain separator for EdDSA key derivation
pub const EDDSA_KEY_DOMAIN: &[u8] = b"orbinum-eddsa-key-v1";

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// ===== Size constant coherence =====

	#[test]
	fn test_min_size_equals_nonce_plus_mac() {
		assert_eq!(MIN_ENCRYPTED_MEMO_SIZE, NONCE_SIZE + MAC_SIZE);
	}

	#[test]
	fn test_max_size_equals_min_plus_memo_data() {
		assert_eq!(
			MAX_ENCRYPTED_MEMO_SIZE,
			MIN_ENCRYPTED_MEMO_SIZE + MEMO_DATA_SIZE
		);
	}

	#[test]
	fn test_memo_data_size_is_76() {
		assert_eq!(MEMO_DATA_SIZE, 76);
	}

	#[test]
	fn test_nonce_size_is_12() {
		assert_eq!(NONCE_SIZE, 12);
	}

	#[test]
	fn test_mac_size_is_16() {
		assert_eq!(MAC_SIZE, 16);
	}

	#[test]
	fn test_max_size_is_104() {
		assert_eq!(MAX_ENCRYPTED_MEMO_SIZE, 104);
	}

	#[test]
	fn test_min_size_is_28() {
		assert_eq!(MIN_ENCRYPTED_MEMO_SIZE, 28);
	}

	// ===== Domain separator uniqueness =====

	#[test]
	fn test_all_domain_separators_unique() {
		let domains = [
			KEY_DOMAIN,
			VIEWING_KEY_DOMAIN,
			NULLIFIER_KEY_DOMAIN,
			EDDSA_KEY_DOMAIN,
		];
		for i in 0..domains.len() {
			for j in (i + 1)..domains.len() {
				assert_ne!(domains[i], domains[j]);
			}
		}
	}

	#[test]
	fn test_domain_separators_non_empty() {
		assert!(!KEY_DOMAIN.is_empty());
		assert!(!VIEWING_KEY_DOMAIN.is_empty());
		assert!(!NULLIFIER_KEY_DOMAIN.is_empty());
		assert!(!EDDSA_KEY_DOMAIN.is_empty());
	}

	#[test]
	fn test_domain_separators_start_with_orbinum() {
		for d in [
			KEY_DOMAIN,
			VIEWING_KEY_DOMAIN,
			NULLIFIER_KEY_DOMAIN,
			EDDSA_KEY_DOMAIN,
		] {
			assert!(
				d.starts_with(b"orbinum-"),
				"expected 'orbinum-' prefix in {:?}",
				d
			);
		}
	}

	#[test]
	fn test_domain_separators_end_with_version() {
		for d in [
			KEY_DOMAIN,
			VIEWING_KEY_DOMAIN,
			NULLIFIER_KEY_DOMAIN,
			EDDSA_KEY_DOMAIN,
		] {
			assert!(d.ends_with(b"-v1"), "expected '-v1' suffix in {:?}", d);
		}
	}

	#[test]
	fn test_key_domain_exact_value() {
		assert_eq!(KEY_DOMAIN, b"orbinum-note-encryption-v1");
	}

	#[test]
	fn test_viewing_key_domain_exact_value() {
		assert_eq!(VIEWING_KEY_DOMAIN, b"orbinum-viewing-key-v1");
	}

	#[test]
	fn test_nullifier_key_domain_exact_value() {
		assert_eq!(NULLIFIER_KEY_DOMAIN, b"orbinum-nullifier-key-v1");
	}

	#[test]
	fn test_eddsa_key_domain_exact_value() {
		assert_eq!(EDDSA_KEY_DOMAIN, b"orbinum-eddsa-key-v1");
	}
}
