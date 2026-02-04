//! SHA-256 key derivation with domain separation for viewing, nullifier, and EdDSA keys

use crate::domain::entities::{
	constants::KEY_DOMAIN,
	types::{EdDSAKey, NullifierKey, ViewingKey},
};
use sha2::{Digest, Sha256};

/// Domain separator for viewing key derivation
const VIEWING_KEY_DOMAIN: &[u8] = b"orbinum-viewing-key-v1";

/// Domain separator for nullifier key derivation
const NULLIFIER_KEY_DOMAIN: &[u8] = b"orbinum-nullifier-key-v1";

/// Domain separator for EdDSA key derivation
const EDDSA_KEY_DOMAIN: &[u8] = b"orbinum-eddsa-key-v1";

/// Derives encryption key from viewing key and commitment
///
/// `SHA256(viewing_key || commitment || domain_separator)`
pub fn derive_encryption_key(viewing_key: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(viewing_key);
	hasher.update(commitment);
	hasher.update(KEY_DOMAIN);

	let hash = hasher.finalize();
	let mut key = [0u8; 32];
	key.copy_from_slice(&hash);
	key
}

/// Derives viewing key from spending key using SHA-256
pub fn derive_viewing_key_from_spending(spending_key: &[u8; 32]) -> ViewingKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(VIEWING_KEY_DOMAIN);

	let hash = hasher.finalize();
	let mut key = [0u8; 32];
	key.copy_from_slice(&hash);
	ViewingKey(key)
}

/// Derives nullifier key from spending key using SHA-256
pub fn derive_nullifier_key_from_spending(spending_key: &[u8; 32]) -> NullifierKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(NULLIFIER_KEY_DOMAIN);

	let hash = hasher.finalize();
	let mut key = [0u8; 32];
	key.copy_from_slice(&hash);
	NullifierKey(key)
}

/// Derives EdDSA key from spending key for circuit signatures
pub fn derive_eddsa_key_from_spending(spending_key: &[u8; 32]) -> EdDSAKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(EDDSA_KEY_DOMAIN);

	let hash = hasher.finalize();
	let mut key = [0u8; 32];
	key.copy_from_slice(&hash);
	EdDSAKey(key)
}

/// Derives viewing key (returns raw bytes)
pub fn derive_viewing_key(spending_key: &[u8; 32]) -> [u8; 32] {
	derive_viewing_key_from_spending(spending_key).0
}

/// Derives nullifier key (returns raw bytes)
pub fn derive_nullifier_key(spending_key: &[u8; 32]) -> [u8; 32] {
	derive_nullifier_key_from_spending(spending_key).0
}

/// Derives EdDSA key (returns raw bytes)
pub fn derive_eddsa_key(spending_key: &[u8; 32]) -> [u8; 32] {
	derive_eddsa_key_from_spending(spending_key).0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// ===== derive_encryption_key Tests =====

	#[test]
	fn test_derive_encryption_key_basic() {
		let viewing_key = [1u8; 32];
		let commitment = [2u8; 32];

		let key = derive_encryption_key(&viewing_key, &commitment);

		assert_eq!(key.len(), 32);
		assert_ne!(key, [0u8; 32]);
	}

	#[test]
	fn test_derive_encryption_key_deterministic() {
		let viewing_key = [42u8; 32];
		let commitment = [99u8; 32];

		let key1 = derive_encryption_key(&viewing_key, &commitment);
		let key2 = derive_encryption_key(&viewing_key, &commitment);

		// Same inputs produce same output
		assert_eq!(key1, key2);
	}

	#[test]
	fn test_derive_encryption_key_different_commitments() {
		let viewing_key = [1u8; 32];
		let commitment1 = [2u8; 32];
		let commitment2 = [3u8; 32];

		let key1 = derive_encryption_key(&viewing_key, &commitment1);
		let key2 = derive_encryption_key(&viewing_key, &commitment2);

		// Different commitments produce different keys
		assert_ne!(key1, key2);
	}

	#[test]
	fn test_derive_encryption_key_different_viewing_keys() {
		let viewing_key1 = [1u8; 32];
		let viewing_key2 = [2u8; 32];
		let commitment = [3u8; 32];

		let key1 = derive_encryption_key(&viewing_key1, &commitment);
		let key2 = derive_encryption_key(&viewing_key2, &commitment);

		// Different viewing keys produce different encryption keys
		assert_ne!(key1, key2);
	}

	#[test]
	fn test_derive_encryption_key_zero_inputs() {
		let viewing_key = [0u8; 32];
		let commitment = [0u8; 32];

		let key = derive_encryption_key(&viewing_key, &commitment);

		// Should still produce valid key
		assert_eq!(key.len(), 32);
		assert_ne!(key, [0u8; 32]);
	}

	#[test]
	fn test_derive_encryption_key_max_inputs() {
		let viewing_key = [255u8; 32];
		let commitment = [255u8; 32];

		let key = derive_encryption_key(&viewing_key, &commitment);

		assert_eq!(key.len(), 32);
		assert_ne!(key, [0u8; 32]);
	}

	// ===== derive_viewing_key_from_spending Tests =====

	#[test]
	fn test_derive_viewing_key_from_spending_basic() {
		let spending_key = [1u8; 32];

		let viewing_key = derive_viewing_key_from_spending(&spending_key);

		assert_eq!(viewing_key.0.len(), 32);
		assert_ne!(viewing_key.0, [0u8; 32]);
	}

	#[test]
	fn test_derive_viewing_key_from_spending_deterministic() {
		let spending_key = [42u8; 32];

		let vk1 = derive_viewing_key_from_spending(&spending_key);
		let vk2 = derive_viewing_key_from_spending(&spending_key);

		// Same spending key produces same viewing key
		assert_eq!(vk1, vk2);
	}

	#[test]
	fn test_derive_viewing_key_from_spending_different_inputs() {
		let spending_key1 = [1u8; 32];
		let spending_key2 = [2u8; 32];

		let vk1 = derive_viewing_key_from_spending(&spending_key1);
		let vk2 = derive_viewing_key_from_spending(&spending_key2);

		// Different spending keys produce different viewing keys
		assert_ne!(vk1, vk2);
	}

	#[test]
	fn test_derive_viewing_key_from_spending_returns_viewing_key_type() {
		let spending_key = [10u8; 32];

		let result = derive_viewing_key_from_spending(&spending_key);

		// Check it returns ViewingKey type
		let _: ViewingKey = result;
	}

	// ===== derive_nullifier_key_from_spending Tests =====

	#[test]
	fn test_derive_nullifier_key_from_spending_basic() {
		let spending_key = [1u8; 32];

		let nullifier_key = derive_nullifier_key_from_spending(&spending_key);

		assert_eq!(nullifier_key.0.len(), 32);
		assert_ne!(nullifier_key.0, [0u8; 32]);
	}

	#[test]
	fn test_derive_nullifier_key_from_spending_deterministic() {
		let spending_key = [42u8; 32];

		let nk1 = derive_nullifier_key_from_spending(&spending_key);
		let nk2 = derive_nullifier_key_from_spending(&spending_key);

		// Same spending key produces same nullifier key
		assert_eq!(nk1, nk2);
	}

	#[test]
	fn test_derive_nullifier_key_from_spending_different_inputs() {
		let spending_key1 = [1u8; 32];
		let spending_key2 = [2u8; 32];

		let nk1 = derive_nullifier_key_from_spending(&spending_key1);
		let nk2 = derive_nullifier_key_from_spending(&spending_key2);

		// Different spending keys produce different nullifier keys
		assert_ne!(nk1, nk2);
	}

	#[test]
	fn test_derive_nullifier_key_from_spending_returns_nullifier_key_type() {
		let spending_key = [10u8; 32];

		let result = derive_nullifier_key_from_spending(&spending_key);

		// Check it returns NullifierKey type
		let _: NullifierKey = result;
	}

	// ===== derive_eddsa_key_from_spending Tests =====

	#[test]
	fn test_derive_eddsa_key_from_spending_basic() {
		let spending_key = [1u8; 32];

		let eddsa_key = derive_eddsa_key_from_spending(&spending_key);

		assert_eq!(eddsa_key.0.len(), 32);
		assert_ne!(eddsa_key.0, [0u8; 32]);
	}

	#[test]
	fn test_derive_eddsa_key_from_spending_deterministic() {
		let spending_key = [42u8; 32];

		let ek1 = derive_eddsa_key_from_spending(&spending_key);
		let ek2 = derive_eddsa_key_from_spending(&spending_key);

		// Same spending key produces same EdDSA key
		assert_eq!(ek1, ek2);
	}

	#[test]
	fn test_derive_eddsa_key_from_spending_different_inputs() {
		let spending_key1 = [1u8; 32];
		let spending_key2 = [2u8; 32];

		let ek1 = derive_eddsa_key_from_spending(&spending_key1);
		let ek2 = derive_eddsa_key_from_spending(&spending_key2);

		// Different spending keys produce different EdDSA keys
		assert_ne!(ek1, ek2);
	}

	#[test]
	fn test_derive_eddsa_key_from_spending_returns_eddsa_key_type() {
		let spending_key = [10u8; 32];

		let result = derive_eddsa_key_from_spending(&spending_key);

		// Check it returns EdDSAKey type
		let _: EdDSAKey = result;
	}

	// ===== Raw Bytes Functions Tests =====

	#[test]
	fn test_derive_viewing_key_raw() {
		let spending_key = [1u8; 32];

		let raw_key = derive_viewing_key(&spending_key);
		let typed_key = derive_viewing_key_from_spending(&spending_key);

		// Raw function should return same bytes as typed function
		assert_eq!(raw_key, typed_key.0);
	}

	#[test]
	fn test_derive_nullifier_key_raw() {
		let spending_key = [1u8; 32];

		let raw_key = derive_nullifier_key(&spending_key);
		let typed_key = derive_nullifier_key_from_spending(&spending_key);

		// Raw function should return same bytes as typed function
		assert_eq!(raw_key, typed_key.0);
	}

	#[test]
	fn test_derive_eddsa_key_raw() {
		let spending_key = [1u8; 32];

		let raw_key = derive_eddsa_key(&spending_key);
		let typed_key = derive_eddsa_key_from_spending(&spending_key);

		// Raw function should return same bytes as typed function
		assert_eq!(raw_key, typed_key.0);
	}

	// ===== Domain Separation Tests =====

	#[test]
	fn test_domain_separation_viewing_vs_nullifier() {
		let spending_key = [42u8; 32];

		let viewing_key = derive_viewing_key(&spending_key);
		let nullifier_key = derive_nullifier_key(&spending_key);

		// Same spending key should produce different keys for different domains
		assert_ne!(viewing_key, nullifier_key);
	}

	#[test]
	fn test_domain_separation_viewing_vs_eddsa() {
		let spending_key = [42u8; 32];

		let viewing_key = derive_viewing_key(&spending_key);
		let eddsa_key = derive_eddsa_key(&spending_key);

		// Different domain separators produce different keys
		assert_ne!(viewing_key, eddsa_key);
	}

	#[test]
	fn test_domain_separation_nullifier_vs_eddsa() {
		let spending_key = [42u8; 32];

		let nullifier_key = derive_nullifier_key(&spending_key);
		let eddsa_key = derive_eddsa_key(&spending_key);

		// All three key types should be distinct
		assert_ne!(nullifier_key, eddsa_key);
	}

	#[test]
	fn test_domain_separation_all_keys_unique() {
		let spending_key = [99u8; 32];

		let viewing_key = derive_viewing_key(&spending_key);
		let nullifier_key = derive_nullifier_key(&spending_key);
		let eddsa_key = derive_eddsa_key(&spending_key);

		// All three should be distinct from each other
		assert_ne!(viewing_key, nullifier_key);
		assert_ne!(viewing_key, eddsa_key);
		assert_ne!(nullifier_key, eddsa_key);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_full_key_derivation_chain() {
		let spending_key = [42u8; 32];

		// Derive all keys from spending key
		let viewing_key = derive_viewing_key_from_spending(&spending_key);
		let nullifier_key = derive_nullifier_key_from_spending(&spending_key);
		let eddsa_key = derive_eddsa_key_from_spending(&spending_key);

		// All keys should be valid (non-zero)
		assert_ne!(viewing_key.0, [0u8; 32]);
		assert_ne!(nullifier_key.0, [0u8; 32]);
		assert_ne!(eddsa_key.0, [0u8; 32]);

		// All keys should be distinct
		assert_ne!(viewing_key.0, nullifier_key.0);
		assert_ne!(viewing_key.0, eddsa_key.0);
		assert_ne!(nullifier_key.0, eddsa_key.0);
	}

	#[test]
	fn test_encryption_key_with_derived_viewing_key() {
		let spending_key = [42u8; 32];
		let commitment = [99u8; 32];

		// Derive viewing key from spending key
		let viewing_key = derive_viewing_key(&spending_key);

		// Use viewing key to derive encryption key
		let encryption_key = derive_encryption_key(&viewing_key, &commitment);

		assert_eq!(encryption_key.len(), 32);
		assert_ne!(encryption_key, [0u8; 32]);
		assert_ne!(encryption_key, viewing_key);
	}

	#[test]
	fn test_multiple_commitments_same_viewing_key() {
		let spending_key = [42u8; 32];
		let viewing_key = derive_viewing_key(&spending_key);

		let commitment1 = [1u8; 32];
		let commitment2 = [2u8; 32];
		let commitment3 = [3u8; 32];

		let enc_key1 = derive_encryption_key(&viewing_key, &commitment1);
		let enc_key2 = derive_encryption_key(&viewing_key, &commitment2);
		let enc_key3 = derive_encryption_key(&viewing_key, &commitment3);

		// Each commitment should produce unique encryption key
		assert_ne!(enc_key1, enc_key2);
		assert_ne!(enc_key1, enc_key3);
		assert_ne!(enc_key2, enc_key3);
	}

	#[test]
	fn test_zero_spending_key() {
		let spending_key = [0u8; 32];

		let viewing_key = derive_viewing_key(&spending_key);
		let nullifier_key = derive_nullifier_key(&spending_key);
		let eddsa_key = derive_eddsa_key(&spending_key);

		// Even zero spending key should produce valid non-zero derived keys
		assert_ne!(viewing_key, [0u8; 32]);
		assert_ne!(nullifier_key, [0u8; 32]);
		assert_ne!(eddsa_key, [0u8; 32]);
	}

	#[test]
	fn test_max_spending_key() {
		let spending_key = [255u8; 32];

		let viewing_key = derive_viewing_key(&spending_key);
		let nullifier_key = derive_nullifier_key(&spending_key);
		let eddsa_key = derive_eddsa_key(&spending_key);

		// All keys should be valid
		assert_ne!(viewing_key, [0u8; 32]);
		assert_ne!(nullifier_key, [0u8; 32]);
		assert_ne!(eddsa_key, [0u8; 32]);
	}

	#[test]
	fn test_reproducibility_across_multiple_calls() {
		let spending_key = [123u8; 32];

		// Call multiple times
		let vk1 = derive_viewing_key(&spending_key);
		let vk2 = derive_viewing_key(&spending_key);
		let vk3 = derive_viewing_key(&spending_key);

		let nk1 = derive_nullifier_key(&spending_key);
		let nk2 = derive_nullifier_key(&spending_key);

		let ek1 = derive_eddsa_key(&spending_key);
		let ek2 = derive_eddsa_key(&spending_key);

		// All calls should produce identical results
		assert_eq!(vk1, vk2);
		assert_eq!(vk2, vk3);
		assert_eq!(nk1, nk2);
		assert_eq!(ek1, ek2);
	}
}
