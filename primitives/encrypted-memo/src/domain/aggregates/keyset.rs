//! Key Set aggregate.
//!
//! Manages all sub-keys derived from a single master spending key.

use crate::domain::{
	services::key_derivation,
	value_objects::{EdDSAKey, NullifierKey, ViewingKey},
};

/// Full key set derived from a single spending key.
///
/// All sub-keys are deterministically derived via SHA-256 with domain separation.
/// The `spending_key` is kept private — access it only through [`KeySet::spending_key`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeySet {
	/// Master spending key (secret — never expose over the wire)
	spending_key: [u8; 32],
	/// Viewing key for memo decryption (safe to share with auditors)
	pub viewing_key: ViewingKey,
	/// Nullifier derivation key
	pub nullifier_key: NullifierKey,
	/// EdDSA signing key for ZK circuits
	pub eddsa_key: EdDSAKey,
}

impl KeySet {
	/// Creates a `KeySet` from pre-derived keys.
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

	/// Derives a full key set from a master spending key.
	pub fn from_spending_key(spending_key: [u8; 32]) -> Self {
		Self {
			spending_key,
			viewing_key: key_derivation::derive_viewing_key_from_spending(&spending_key),
			nullifier_key: key_derivation::derive_nullifier_key_from_spending(&spending_key),
			eddsa_key: key_derivation::derive_eddsa_key_from_spending(&spending_key),
		}
	}

	/// Returns a reference to the master spending key.
	///
	/// Use with care — never serialize or transmit this value.
	pub fn spending_key(&self) -> &[u8; 32] {
		&self.spending_key
	}

	/// Exports the viewing key for an auditor (read-only access).
	pub fn export_viewing_key(&self) -> ViewingKey {
		self.viewing_key.clone()
	}

	/// Returns `true` when `vk` matches the viewing key in this key set.
	pub fn matches_viewing_key(&self, vk: &ViewingKey) -> bool {
		self.viewing_key == *vk
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// ===== KeySet::new Tests =====

	#[test]
	fn test_keyset_new() {
		let spending = [1u8; 32];
		let viewing = ViewingKey::from_bytes([2u8; 32]);
		let nullifier = NullifierKey::from_bytes([3u8; 32]);
		let eddsa = EdDSAKey::from_bytes([4u8; 32]);

		let keyset = KeySet::new(spending, viewing.clone(), nullifier.clone(), eddsa.clone());

		assert_eq!(keyset.spending_key(), &spending);
		assert_eq!(keyset.viewing_key, viewing);
		assert_eq!(keyset.nullifier_key, nullifier);
		assert_eq!(keyset.eddsa_key, eddsa);
	}

	#[test]
	fn test_keyset_new_zero_keys() {
		let spending = [0u8; 32];
		let viewing = ViewingKey::from_bytes([0u8; 32]);
		let nullifier = NullifierKey::from_bytes([0u8; 32]);
		let eddsa = EdDSAKey::from_bytes([0u8; 32]);

		let keyset = KeySet::new(spending, viewing.clone(), nullifier.clone(), eddsa.clone());

		assert_eq!(keyset.spending_key(), &[0u8; 32]);
		assert_eq!(keyset.viewing_key, viewing);
	}

	#[test]
	fn test_keyset_new_max_keys() {
		let spending = [255u8; 32];
		let viewing = ViewingKey::from_bytes([255u8; 32]);
		let nullifier = NullifierKey::from_bytes([255u8; 32]);
		let eddsa = EdDSAKey::from_bytes([255u8; 32]);

		let keyset = KeySet::new(spending, viewing.clone(), nullifier.clone(), eddsa.clone());

		assert_eq!(keyset.spending_key(), &[255u8; 32]);
		assert_eq!(keyset.viewing_key, viewing);
	}

	// ===== KeySet::from_spending_key Tests =====

	#[test]
	fn test_from_spending_key() {
		let spending_key = [42u8; 32];
		let keyset = KeySet::from_spending_key(spending_key);

		assert_eq!(keyset.spending_key(), &spending_key);
		// All derived keys should be non-zero (SHA256 output)
		assert_ne!(keyset.viewing_key.as_bytes(), &[0u8; 32]);
		assert_ne!(keyset.nullifier_key.as_bytes(), &[0u8; 32]);
		assert_ne!(keyset.eddsa_key.as_bytes(), &[0u8; 32]);
	}

	#[test]
	fn test_from_spending_key_deterministic() {
		let spending_key = [100u8; 32];
		let keyset1 = KeySet::from_spending_key(spending_key);
		let keyset2 = KeySet::from_spending_key(spending_key);

		assert_eq!(keyset1.viewing_key, keyset2.viewing_key);
		assert_eq!(keyset1.nullifier_key, keyset2.nullifier_key);
		assert_eq!(keyset1.eddsa_key, keyset2.eddsa_key);
	}

	#[test]
	fn test_from_spending_key_different_inputs() {
		let spending_key1 = [1u8; 32];
		let spending_key2 = [2u8; 32];

		let keyset1 = KeySet::from_spending_key(spending_key1);
		let keyset2 = KeySet::from_spending_key(spending_key2);

		// Different spending keys should produce different derived keys
		assert_ne!(keyset1.viewing_key, keyset2.viewing_key);
		assert_ne!(keyset1.nullifier_key, keyset2.nullifier_key);
		assert_ne!(keyset1.eddsa_key, keyset2.eddsa_key);
	}

	#[test]
	fn test_from_spending_key_zero() {
		let spending_key = [0u8; 32];
		let keyset = KeySet::from_spending_key(spending_key);

		assert_eq!(keyset.spending_key(), &[0u8; 32]);
		// Even zero spending key should produce non-zero derived keys
		assert_ne!(keyset.viewing_key.as_bytes(), &[0u8; 32]);
	}

	#[test]
	fn test_from_spending_key_sequential() {
		let mut spending_key = [0u8; 32];
		for (i, byte) in spending_key.iter_mut().enumerate() {
			*byte = i as u8;
		}

		let keyset = KeySet::from_spending_key(spending_key);

		assert_eq!(keyset.spending_key(), &spending_key);
		assert_ne!(keyset.viewing_key.as_bytes(), &[0u8; 32]);
	}

	// ===== export_viewing_key Tests =====

	#[test]
	fn test_export_viewing_key() {
		let spending_key = [42u8; 32];
		let keyset = KeySet::from_spending_key(spending_key);

		let exported = keyset.export_viewing_key();

		assert_eq!(exported, keyset.viewing_key);
	}

	#[test]
	fn test_export_viewing_key_immutable() {
		let spending_key = [10u8; 32];
		let keyset = KeySet::from_spending_key(spending_key);

		let exported1 = keyset.export_viewing_key();
		let exported2 = keyset.export_viewing_key();

		// Should always return same key
		assert_eq!(exported1, exported2);
		assert_eq!(exported1, keyset.viewing_key);
	}

	#[test]
	fn test_export_viewing_key_different_keysets() {
		let keyset1 = KeySet::from_spending_key([1u8; 32]);
		let keyset2 = KeySet::from_spending_key([2u8; 32]);

		let vk1 = keyset1.export_viewing_key();
		let vk2 = keyset2.export_viewing_key();

		// Different keysets should export different viewing keys
		assert_ne!(vk1, vk2);
	}

	// ===== matches_viewing_key Tests =====

	#[test]
	fn test_matches_viewing_key_true() {
		let spending_key = [42u8; 32];
		let keyset = KeySet::from_spending_key(spending_key);
		let vk = keyset.viewing_key.clone();

		assert!(keyset.matches_viewing_key(&vk));
	}

	#[test]
	fn test_matches_viewing_key_false() {
		let keyset1 = KeySet::from_spending_key([1u8; 32]);
		let keyset2 = KeySet::from_spending_key([2u8; 32]);

		assert!(!keyset1.matches_viewing_key(&keyset2.viewing_key));
	}

	#[test]
	fn test_matches_viewing_key_exported() {
		let spending_key = [99u8; 32];
		let keyset = KeySet::from_spending_key(spending_key);
		let exported_vk = keyset.export_viewing_key();

		assert!(keyset.matches_viewing_key(&exported_vk));
	}

	#[test]
	fn test_matches_viewing_key_different() {
		let keyset = KeySet::from_spending_key([10u8; 32]);
		let other_vk = ViewingKey::from_bytes([99u8; 32]);

		assert!(!keyset.matches_viewing_key(&other_vk));
	}

	// ===== Clone and PartialEq Tests =====

	#[test]
	fn test_keyset_clone() {
		let spending_key = [42u8; 32];
		let keyset1 = KeySet::from_spending_key(spending_key);
		let keyset2 = keyset1.clone();

		assert_eq!(keyset1, keyset2);
		assert_eq!(keyset1.spending_key(), keyset2.spending_key());
		assert_eq!(keyset1.viewing_key, keyset2.viewing_key);
		assert_eq!(keyset1.nullifier_key, keyset2.nullifier_key);
		assert_eq!(keyset1.eddsa_key, keyset2.eddsa_key);
	}

	#[test]
	fn test_keyset_partial_eq() {
		let spending_key = [42u8; 32];
		let keyset1 = KeySet::from_spending_key(spending_key);
		let keyset2 = KeySet::from_spending_key(spending_key);

		assert_eq!(keyset1, keyset2);
	}

	#[test]
	fn test_keyset_not_equal() {
		let keyset1 = KeySet::from_spending_key([1u8; 32]);
		let keyset2 = KeySet::from_spending_key([2u8; 32]);

		assert_ne!(keyset1, keyset2);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_full_derivation_chain() {
		let spending_key = [123u8; 32];
		let keyset = KeySet::from_spending_key(spending_key);

		// All keys should be derived and distinct
		assert_eq!(keyset.spending_key(), &spending_key);
		assert_ne!(keyset.viewing_key.as_bytes(), &spending_key);
		assert_ne!(keyset.nullifier_key.as_bytes(), &spending_key);
		assert_ne!(keyset.eddsa_key.as_bytes(), &spending_key);

		// Derived keys should differ from each other
		assert_ne!(
			keyset.viewing_key.as_bytes(),
			keyset.nullifier_key.as_bytes()
		);
		assert_ne!(keyset.viewing_key.as_bytes(), keyset.eddsa_key.as_bytes());
		assert_ne!(keyset.nullifier_key.as_bytes(), keyset.eddsa_key.as_bytes());
	}

	#[test]
	fn test_viewing_key_workflow() {
		let spending_key = [200u8; 32];
		let wallet_keyset = KeySet::from_spending_key(spending_key);

		// Export viewing key for auditor
		let auditor_vk = wallet_keyset.export_viewing_key();

		// Auditor can verify it matches
		assert!(wallet_keyset.matches_viewing_key(&auditor_vk));

		// Different wallet's viewing key should not match
		let other_keyset = KeySet::from_spending_key([201u8; 32]);
		let other_vk = other_keyset.export_viewing_key();
		assert!(!wallet_keyset.matches_viewing_key(&other_vk));
	}

	#[test]
	fn test_keyset_reproducibility() {
		let spending_key = [77u8; 32];

		// Create keysets at different times
		let keyset1 = KeySet::from_spending_key(spending_key);
		let keyset2 = KeySet::from_spending_key(spending_key);

		// Should be identical
		assert_eq!(keyset1, keyset2);

		// Export should also match
		assert_eq!(keyset1.export_viewing_key(), keyset2.export_viewing_key());
	}

	#[test]
	fn test_multiple_keysets_independent() {
		let keys = [
			KeySet::from_spending_key([1u8; 32]),
			KeySet::from_spending_key([2u8; 32]),
			KeySet::from_spending_key([3u8; 32]),
		];

		// All keysets should be distinct
		for i in 0..keys.len() {
			for j in (i + 1)..keys.len() {
				assert_ne!(keys[i], keys[j]);
				assert_ne!(keys[i].viewing_key, keys[j].viewing_key);
				assert_ne!(keys[i].nullifier_key, keys[j].nullifier_key);
				assert_ne!(keys[i].eddsa_key, keys[j].eddsa_key);
			}
		}
	}
}
