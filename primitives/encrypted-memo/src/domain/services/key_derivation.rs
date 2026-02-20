//! SHA-256 key derivation with domain separation.
//!
//! All functions return the strongly-typed value objects defined in
//! `domain::value_objects`.

use crate::domain::value_objects::{
	constants::{EDDSA_KEY_DOMAIN, KEY_DOMAIN, NULLIFIER_KEY_DOMAIN, VIEWING_KEY_DOMAIN},
	EdDSAKey, NullifierKey, ViewingKey,
};
use sha2::{Digest, Sha256};

/// Derives the per-note encryption key from a viewing key and commitment.
///
/// `SHA256(viewing_key || commitment || KEY_DOMAIN)`
pub fn derive_encryption_key(viewing_key: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(viewing_key);
	hasher.update(commitment);
	hasher.update(KEY_DOMAIN);
	hasher.finalize().into()
}

/// Derives the viewing key from a spending key.
///
/// `SHA256(spending_key || VIEWING_KEY_DOMAIN)`
pub fn derive_viewing_key_from_spending(spending_key: &[u8; 32]) -> ViewingKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(VIEWING_KEY_DOMAIN);
	ViewingKey(hasher.finalize().into())
}

/// Derives the nullifier key from a spending key.
///
/// `SHA256(spending_key || NULLIFIER_KEY_DOMAIN)`
pub fn derive_nullifier_key_from_spending(spending_key: &[u8; 32]) -> NullifierKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(NULLIFIER_KEY_DOMAIN);
	NullifierKey(hasher.finalize().into())
}

/// Derives the EdDSA circuit signing key from a spending key.
///
/// `SHA256(spending_key || EDDSA_KEY_DOMAIN)`
pub fn derive_eddsa_key_from_spending(spending_key: &[u8; 32]) -> EdDSAKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(EDDSA_KEY_DOMAIN);
	EdDSAKey(hasher.finalize().into())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// ===== derive_encryption_key =====

	#[test]
	fn test_derive_encryption_key_basic() {
		let key = derive_encryption_key(&[1u8; 32], &[2u8; 32]);
		assert_ne!(key, [0u8; 32]);
	}

	#[test]
	fn test_derive_encryption_key_deterministic() {
		let k1 = derive_encryption_key(&[42u8; 32], &[99u8; 32]);
		let k2 = derive_encryption_key(&[42u8; 32], &[99u8; 32]);
		assert_eq!(k1, k2);
	}

	#[test]
	fn test_derive_encryption_key_different_commitments() {
		let vk = [1u8; 32];
		assert_ne!(
			derive_encryption_key(&vk, &[2u8; 32]),
			derive_encryption_key(&vk, &[3u8; 32])
		);
	}

	#[test]
	fn test_derive_encryption_key_different_viewing_keys() {
		let comm = [3u8; 32];
		assert_ne!(
			derive_encryption_key(&[1u8; 32], &comm),
			derive_encryption_key(&[2u8; 32], &comm)
		);
	}

	// ===== derive_viewing_key_from_spending =====

	#[test]
	fn test_derive_viewing_key_basic() {
		let vk = derive_viewing_key_from_spending(&[1u8; 32]);
		assert_ne!(vk.0, [0u8; 32]);
	}

	#[test]
	fn test_derive_viewing_key_deterministic() {
		assert_eq!(
			derive_viewing_key_from_spending(&[42u8; 32]),
			derive_viewing_key_from_spending(&[42u8; 32]),
		);
	}

	#[test]
	fn test_derive_viewing_key_different_inputs() {
		assert_ne!(
			derive_viewing_key_from_spending(&[1u8; 32]),
			derive_viewing_key_from_spending(&[2u8; 32]),
		);
	}

	// ===== derive_nullifier_key_from_spending =====

	#[test]
	fn test_derive_nullifier_key_basic() {
		let nk = derive_nullifier_key_from_spending(&[1u8; 32]);
		assert_ne!(nk.0, [0u8; 32]);
	}

	#[test]
	fn test_derive_nullifier_key_deterministic() {
		assert_eq!(
			derive_nullifier_key_from_spending(&[42u8; 32]),
			derive_nullifier_key_from_spending(&[42u8; 32]),
		);
	}

	// ===== derive_eddsa_key_from_spending =====

	#[test]
	fn test_derive_eddsa_key_basic() {
		let ek = derive_eddsa_key_from_spending(&[1u8; 32]);
		assert_ne!(ek.0, [0u8; 32]);
	}

	#[test]
	fn test_derive_eddsa_key_deterministic() {
		assert_eq!(
			derive_eddsa_key_from_spending(&[42u8; 32]),
			derive_eddsa_key_from_spending(&[42u8; 32]),
		);
	}

	// ===== Domain Separation =====

	#[test]
	fn test_domain_separation_all_keys_unique() {
		let sk = [99u8; 32];
		let vk = derive_viewing_key_from_spending(&sk);
		let nk = derive_nullifier_key_from_spending(&sk);
		let ek = derive_eddsa_key_from_spending(&sk);
		assert_ne!(vk.0, nk.0);
		assert_ne!(vk.0, ek.0);
		assert_ne!(nk.0, ek.0);
	}

	// ===== Integration =====

	#[test]
	fn test_full_derivation_chain() {
		let sk = [42u8; 32];
		let vk = derive_viewing_key_from_spending(&sk);
		let nk = derive_nullifier_key_from_spending(&sk);
		let ek = derive_eddsa_key_from_spending(&sk);
		let enc = derive_encryption_key(vk.as_bytes(), &[99u8; 32]);
		assert_ne!(enc, [0u8; 32]);
		assert_ne!(enc, vk.0);
		assert_ne!(vk.0, nk.0);
		assert_ne!(vk.0, ek.0);
	}

	#[test]
	fn test_zero_spending_key_produces_non_zero_keys() {
		let sk = [0u8; 32];
		assert_ne!(derive_viewing_key_from_spending(&sk).0, [0u8; 32]);
		assert_ne!(derive_nullifier_key_from_spending(&sk).0, [0u8; 32]);
		assert_ne!(derive_eddsa_key_from_spending(&sk).0, [0u8; 32]);
	}

	#[test]
	fn test_derive_nullifier_key_different_inputs() {
		assert_ne!(
			derive_nullifier_key_from_spending(&[1u8; 32]),
			derive_nullifier_key_from_spending(&[2u8; 32]),
		);
	}

	#[test]
	fn test_derive_eddsa_key_different_inputs() {
		assert_ne!(
			derive_eddsa_key_from_spending(&[1u8; 32]),
			derive_eddsa_key_from_spending(&[2u8; 32]),
		);
	}

	#[test]
	fn test_all_derived_keys_differ_from_spending_key() {
		let sk = [42u8; 32];
		// Domain separation guarantees derived keys ≠ raw spending key
		assert_ne!(derive_viewing_key_from_spending(&sk).0, sk);
		assert_ne!(derive_nullifier_key_from_spending(&sk).0, sk);
		assert_ne!(derive_eddsa_key_from_spending(&sk).0, sk);
	}

	#[test]
	fn test_derive_encryption_key_all_zero_inputs_non_zero() {
		// SHA-256 of zeros is never itself zero
		let result = derive_encryption_key(&[0u8; 32], &[0u8; 32]);
		assert_ne!(result, [0u8; 32]);
	}

	#[test]
	fn test_derive_encryption_key_output_length() {
		let key = derive_encryption_key(&[1u8; 32], &[2u8; 32]);
		assert_eq!(key.len(), 32);
	}
}
