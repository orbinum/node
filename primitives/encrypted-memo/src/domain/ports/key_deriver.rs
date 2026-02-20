//! Key Deriver port.
//!
//! Abstract interface for deriving sub-keys from a master spending key.
//! Implement this trait in the services layer.

use crate::domain::value_objects::{EdDSAKey, NullifierKey, ViewingKey};

/// Port for deterministic key derivation from a spending key.
pub trait KeyDeriver {
	/// Derives the viewing key from a spending key.
	fn derive_viewing(&self, spending_key: &[u8; 32]) -> ViewingKey;

	/// Derives the nullifier key from a spending key.
	fn derive_nullifier(&self, spending_key: &[u8; 32]) -> NullifierKey;

	/// Derives the EdDSA circuit signing key from a spending key.
	fn derive_eddsa(&self, spending_key: &[u8; 32]) -> EdDSAKey;

	/// Derives the per-note encryption key from a viewing key and commitment.
	///
	/// `SHA256(viewing_key || commitment || KEY_DOMAIN)`
	fn derive_encryption_key(&self, viewing_key: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32];
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::domain::value_objects::{EdDSAKey, NullifierKey, ViewingKey};

	/// Mock that echoes the spending_key bytes back as each derived key and
	/// XORs viewing_key with commitment for the encryption key.
	struct MockDeriver;
	impl KeyDeriver for MockDeriver {
		fn derive_viewing(&self, k: &[u8; 32]) -> ViewingKey {
			ViewingKey(*k)
		}
		fn derive_nullifier(&self, k: &[u8; 32]) -> NullifierKey {
			NullifierKey(*k)
		}
		fn derive_eddsa(&self, k: &[u8; 32]) -> EdDSAKey {
			EdDSAKey(*k)
		}
		fn derive_encryption_key(&self, vk: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
			let mut r = [0u8; 32];
			for i in 0..32 {
				r[i] = vk[i] ^ c[i];
			}
			r
		}
	}

	const SK: [u8; 32] = [42u8; 32];

	#[test]
	fn test_derive_viewing_returns_viewing_key() {
		assert_eq!(MockDeriver.derive_viewing(&SK).0, SK);
	}

	#[test]
	fn test_derive_nullifier_returns_nullifier_key() {
		assert_eq!(MockDeriver.derive_nullifier(&SK).0, SK);
	}

	#[test]
	fn test_derive_eddsa_returns_eddsa_key() {
		assert_eq!(MockDeriver.derive_eddsa(&SK).0, SK);
	}

	#[test]
	fn test_derive_encryption_key_xor() {
		let vk = [0x0Fu8; 32];
		let com = [0xF0u8; 32];
		let result = MockDeriver.derive_encryption_key(&vk, &com);
		assert_eq!(result, [0xFFu8; 32]); // 0x0F ^ 0xF0 = 0xFF
	}

	#[test]
	fn test_derive_encryption_key_zero_commitment() {
		// XOR with zero identity: result == viewing_key
		let vk = [7u8; 32];
		assert_eq!(MockDeriver.derive_encryption_key(&vk, &[0u8; 32]), vk);
	}

	#[test]
	fn test_all_keys_derived_from_same_spending_key() {
		let vk = MockDeriver.derive_viewing(&SK);
		let nk = MockDeriver.derive_nullifier(&SK);
		let ek = MockDeriver.derive_eddsa(&SK);
		assert_eq!(vk.0, SK);
		assert_eq!(nk.0, SK);
		assert_eq!(ek.0, SK);
	}
}
