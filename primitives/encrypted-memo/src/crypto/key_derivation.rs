//! Key derivation functions for encrypted memos
//!
//! This module provides functions to derive various keys from a spending key:
//! - Encryption keys (per-memo, derived from viewing key + commitment)
//! - Viewing keys (for memo decryption)
//! - Nullifier keys (for spending)
//! - EdDSA keys (for circuit ownership proofs)

use crate::core::{constants::KEY_DOMAIN, types::{EdDSAKey, NullifierKey, ViewingKey}};
use sha2::{Digest, Sha256};

/// Domain separator for viewing key derivation
const VIEWING_KEY_DOMAIN: &[u8] = b"orbinum-viewing-key-v1";

/// Domain separator for nullifier key derivation
const NULLIFIER_KEY_DOMAIN: &[u8] = b"orbinum-nullifier-key-v1";

/// Domain separator for EdDSA key derivation
const EDDSA_KEY_DOMAIN: &[u8] = b"orbinum-eddsa-key-v1";

/// Derive encryption/decryption key from viewing key and commitment
///
/// Uses SHA-256 with domain separation for key derivation:
/// `key = SHA256(viewing_key || commitment || domain_separator)`
///
/// # Security
///
/// Each note gets a unique key because the commitment is unique.
/// This provides:
/// - Forward secrecy (compromising one key doesn't reveal others)
/// - Unlinkability (same viewing key produces different ciphertexts)
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

/// Derive viewing key from spending key
///
/// Uses SHA-256 with domain separation:
/// `viewing_key = SHA256(spending_key || "orbinum-viewing-key-v1")`
///
/// # Security
///
/// - The viewing key cannot be used to derive the spending key
/// - Different domain separator ensures key separation
pub fn derive_viewing_key_from_spending(spending_key: &[u8; 32]) -> ViewingKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(VIEWING_KEY_DOMAIN);

	let hash = hasher.finalize();
	let mut key = [0u8; 32];
	key.copy_from_slice(&hash);
	ViewingKey(key)
}

/// Derive nullifier key from spending key
///
/// Uses SHA-256 with domain separation:
/// `nullifier_key = SHA256(spending_key || "orbinum-nullifier-key-v1")`
pub fn derive_nullifier_key_from_spending(spending_key: &[u8; 32]) -> NullifierKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(NULLIFIER_KEY_DOMAIN);

	let hash = hasher.finalize();
	let mut key = [0u8; 32];
	key.copy_from_slice(&hash);
	NullifierKey(key)
}

/// Derive EdDSA key from spending key
///
/// Uses SHA-256 with domain separation:
/// `eddsa_key = SHA256(spending_key || "orbinum-eddsa-key-v1")`
///
/// This key is used for signing ownership proofs in ZK circuits.
pub fn derive_eddsa_key_from_spending(spending_key: &[u8; 32]) -> EdDSAKey {
	let mut hasher = Sha256::new();
	hasher.update(spending_key);
	hasher.update(EDDSA_KEY_DOMAIN);

	let hash = hasher.finalize();
	let mut key = [0u8; 32];
	key.copy_from_slice(&hash);
	EdDSAKey(key)
}

/// Derive viewing key directly (convenience function, returns raw bytes)
pub fn derive_viewing_key(spending_key: &[u8; 32]) -> [u8; 32] {
	derive_viewing_key_from_spending(spending_key).0
}

/// Derive nullifier key directly (convenience function, returns raw bytes)
pub fn derive_nullifier_key(spending_key: &[u8; 32]) -> [u8; 32] {
	derive_nullifier_key_from_spending(spending_key).0
}

/// Derive EdDSA key directly (convenience function, returns raw bytes)
pub fn derive_eddsa_key(spending_key: &[u8; 32]) -> [u8; 32] {
	derive_eddsa_key_from_spending(spending_key).0
}
