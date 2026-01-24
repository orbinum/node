//! KeySet management for shielded wallets
//!
//! This module provides the KeySet abstraction that manages all keys
//! derived from a single spending key.

use crate::core::types::{EdDSAKey, MemoData, NullifierKey, ViewingKey};
use crate::crypto::{encryption, key_derivation};

/// Full key set derived from a single spending key
///
/// This contains all keys needed for a shielded wallet:
/// - Spending key: Required to spend funds (keep secret!)
/// - Viewing key: Required to decrypt memos (can be shared with auditors)
/// - Nullifier key: Required to derive nullifiers
/// - EdDSA key: Required to sign ownership proofs in ZK circuits
///
/// ## Key Hierarchy
///
/// ```text
/// spending_key (master secret)
///       │
///       ├── viewing_key = SHA256(spending_key || "orbinum-viewing-key-v1")
///       ├── nullifier_key = SHA256(spending_key || "orbinum-nullifier-key-v1")
///       └── eddsa_key = SHA256(spending_key || "orbinum-eddsa-key-v1")
/// ```
///
/// ## Usage
///
/// ```rust,ignore
/// use fp_encrypted_memo::models::keyset::KeySet;
///
/// // Derive all keys from spending key
/// let keys = KeySet::from_spending_key(spending_key);
///
/// // Share viewing key with auditor (read-only access)
/// let auditor_key = keys.export_viewing_key();
///
/// // Use EdDSA key for circuit proofs
/// let sig = eddsa_sign(&keys.eddsa_key, &commitment);
///
/// // Keep spending key secret
/// let spend_key = keys.spending_key;
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeySet {
	/// Master spending key (keep secret!)
	pub spending_key: [u8; 32],
	/// Viewing key for memo decryption (can be shared)
	pub viewing_key: ViewingKey,
	/// Nullifier derivation key
	pub nullifier_key: NullifierKey,
	/// EdDSA signing key for circuit ownership proofs
	pub eddsa_key: EdDSAKey,
}

impl KeySet {
	/// Create new KeySet with all keys
	pub fn new(
		spending_key: [u8; 32],
		viewing_key: ViewingKey,
		nullifier_key: NullifierKey,
		eddsa_key: EdDSAKey,
	) -> Self {
		Self {
			spending_key,
			viewing_key,
			nullifier_key,
			eddsa_key,
		}
	}

	/// Derive full key set from spending key
	pub fn from_spending_key(spending_key: [u8; 32]) -> Self {
		Self {
			spending_key,
			viewing_key: key_derivation::derive_viewing_key_from_spending(&spending_key),
			nullifier_key: key_derivation::derive_nullifier_key_from_spending(&spending_key),
			eddsa_key: key_derivation::derive_eddsa_key_from_spending(&spending_key),
		}
	}

	/// Export viewing key only (for sharing with auditors)
	///
	/// This creates a read-only view of the wallet that can:
	/// - Decrypt transaction memos
	/// - View balances and transaction history
	///
	/// This CANNOT:
	/// - Spend funds
	/// - Create new transactions
	pub fn export_viewing_key(&self) -> ViewingKey {
		self.viewing_key.clone()
	}

	/// Check if a viewing key matches this key set
	pub fn matches_viewing_key(&self, vk: &ViewingKey) -> bool {
		self.viewing_key == *vk
	}

	/// Try to decrypt a memo using this keyset's viewing key
	///
	/// Returns `Some(MemoData)` if decryption succeeds (note belongs to this key).
	/// Returns `None` if decryption fails (note doesn't belong to us).
	pub fn try_decrypt(&self, encrypted: &[u8], commitment: &[u8; 32]) -> Option<MemoData> {
		encryption::try_decrypt_memo(encrypted, commitment, &self.viewing_key.0)
	}

	/// Decrypt a memo using this keyset's viewing key
	pub fn decrypt(
		&self,
		encrypted: &[u8],
		commitment: &[u8; 32],
	) -> Result<MemoData, crate::core::error::MemoError> {
		encryption::decrypt_memo(encrypted, commitment, &self.viewing_key.0)
	}
}
