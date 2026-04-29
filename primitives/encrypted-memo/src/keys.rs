//! Key types and derivation for Orbinum shielded transactions.
//!
//! All sub-keys are derived from a single 32-byte spending key via SHA-256
//! with domain separation. The spending key itself is never exposed over the wire.
//!
//! # Key hierarchy
//!
//! ```text
//! spending_key
//!   ├── viewing_key     SHA256(sk || "orbinum-viewing-key-v1")
//!   ├── nullifier_key   SHA256(sk || "orbinum-nullifier-key-v1")
//!   └── eddsa_key       SHA256(sk || "orbinum-eddsa-key-v1")
//!
//! encryption_key(commitment)  SHA256(viewing_key || commitment || "orbinum-note-encryption-v1")
//! ```

use sha2::{Digest, Sha256};

// ─── Domain separators ────────────────────────────────────────────────────────

const VIEWING_KEY_DOMAIN: &[u8] = b"orbinum-viewing-key-v1";
const NULLIFIER_KEY_DOMAIN: &[u8] = b"orbinum-nullifier-key-v1";
const EDDSA_KEY_DOMAIN: &[u8] = b"orbinum-eddsa-key-v1";
pub(crate) const KEY_DOMAIN: &[u8] = b"orbinum-note-encryption-v1";

// ─── Key types ────────────────────────────────────────────────────────────────

macro_rules! key_newtype {
	($name:ident, $doc:literal) => {
		#[doc = $doc]
		#[derive(Clone, PartialEq, Eq, Debug)]
		#[cfg_attr(
			all(feature = "parity-scale-codec", feature = "scale-info"),
			derive(
				parity_scale_codec::Encode,
				parity_scale_codec::Decode,
				scale_info::TypeInfo
			)
		)]
		pub struct $name(pub [u8; 32]);

		impl $name {
			/// Creates a key from raw bytes.
			pub fn from_bytes(bytes: [u8; 32]) -> Self {
				Self(bytes)
			}

			/// Returns the raw key bytes.
			pub fn as_bytes(&self) -> &[u8; 32] {
				&self.0
			}
		}

		impl AsRef<[u8; 32]> for $name {
			fn as_ref(&self) -> &[u8; 32] {
				&self.0
			}
		}

		impl From<[u8; 32]> for $name {
			fn from(bytes: [u8; 32]) -> Self {
				Self(bytes)
			}
		}
	};
}

key_newtype!(
	ViewingKey,
	"Read-only key for memo decryption. Safe to share with auditors."
);
key_newtype!(
	NullifierKey,
	"Key for deriving note nullifiers. Must remain secret."
);
key_newtype!(
	EdDSAKey,
	"EdDSA circuit signing key derived from the spending key."
);

// ─── KeySet ───────────────────────────────────────────────────────────────────

/// Full key set derived from a single spending key.
///
/// The `spending_key` is kept private. Access it only via [`KeySet::spending_key`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeySet {
	spending_key: [u8; 32],
	/// Viewing key for memo decryption (safe to share with auditors).
	pub viewing_key: ViewingKey,
	/// Nullifier derivation key (keep secret).
	pub nullifier_key: NullifierKey,
	/// EdDSA signing key for ZK circuits (keep secret).
	pub eddsa_key: EdDSAKey,
}

impl KeySet {
	/// Derives a full key set from a master spending key.
	pub fn from_spending_key(spending_key: [u8; 32]) -> Self {
		Self {
			spending_key,
			viewing_key: derive_viewing_key_from_spending(&spending_key),
			nullifier_key: derive_nullifier_key_from_spending(&spending_key),
			eddsa_key: derive_eddsa_key_from_spending(&spending_key),
		}
	}

	/// Creates a `KeySet` from already-derived keys.
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

// ─── Derivation functions ─────────────────────────────────────────────────────

/// Derives the viewing key: `SHA256(spending_key || VIEWING_KEY_DOMAIN)`
pub fn derive_viewing_key_from_spending(spending_key: &[u8; 32]) -> ViewingKey {
	let mut h = Sha256::new();
	h.update(spending_key);
	h.update(VIEWING_KEY_DOMAIN);
	ViewingKey(h.finalize().into())
}

/// Derives the nullifier key: `SHA256(spending_key || NULLIFIER_KEY_DOMAIN)`
pub fn derive_nullifier_key_from_spending(spending_key: &[u8; 32]) -> NullifierKey {
	let mut h = Sha256::new();
	h.update(spending_key);
	h.update(NULLIFIER_KEY_DOMAIN);
	NullifierKey(h.finalize().into())
}

/// Derives the EdDSA circuit key: `SHA256(spending_key || EDDSA_KEY_DOMAIN)`
pub fn derive_eddsa_key_from_spending(spending_key: &[u8; 32]) -> EdDSAKey {
	let mut h = Sha256::new();
	h.update(spending_key);
	h.update(EDDSA_KEY_DOMAIN);
	EdDSAKey(h.finalize().into())
}

/// Derives the per-note encryption key: `SHA256(viewing_key || commitment || KEY_DOMAIN)`
pub(crate) fn derive_encryption_key(viewing_key: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32] {
	let mut h = Sha256::new();
	h.update(viewing_key);
	h.update(commitment);
	h.update(KEY_DOMAIN);
	h.finalize().into()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;

	const SK: [u8; 32] = [42u8; 32];

	// ── Key newtype API ───────────────────────────────────────────────────────

	#[test]
	fn key_from_bytes_roundtrip() {
		let raw = [7u8; 32];
		assert_eq!(ViewingKey::from_bytes(raw).as_bytes(), &raw);
		assert_eq!(NullifierKey::from_bytes(raw).as_bytes(), &raw);
		assert_eq!(EdDSAKey::from_bytes(raw).as_bytes(), &raw);
	}

	#[test]
	fn key_from_trait() {
		let vk: ViewingKey = [1u8; 32].into();
		assert_eq!(vk.0, [1u8; 32]);
	}

	#[test]
	fn key_as_ref() {
		let vk = ViewingKey::from_bytes([3u8; 32]);
		let r: &[u8; 32] = vk.as_ref();
		assert_eq!(r, &[3u8; 32]);
	}

	// ── Domain separation ─────────────────────────────────────────────────────

	#[test]
	fn domain_separators_are_unique() {
		let domains = [
			VIEWING_KEY_DOMAIN,
			NULLIFIER_KEY_DOMAIN,
			EDDSA_KEY_DOMAIN,
			KEY_DOMAIN,
		];
		for i in 0..domains.len() {
			for j in (i + 1)..domains.len() {
				assert_ne!(domains[i], domains[j]);
			}
		}
	}

	#[test]
	fn derived_keys_differ_from_each_other() {
		let vk = derive_viewing_key_from_spending(&SK);
		let nk = derive_nullifier_key_from_spending(&SK);
		let ek = derive_eddsa_key_from_spending(&SK);
		assert_ne!(vk.0, nk.0);
		assert_ne!(vk.0, ek.0);
		assert_ne!(nk.0, ek.0);
	}

	#[test]
	fn derived_keys_differ_from_spending_key() {
		assert_ne!(derive_viewing_key_from_spending(&SK).0, SK);
		assert_ne!(derive_nullifier_key_from_spending(&SK).0, SK);
		assert_ne!(derive_eddsa_key_from_spending(&SK).0, SK);
	}

	#[test]
	fn derivation_is_deterministic() {
		assert_eq!(
			derive_viewing_key_from_spending(&SK),
			derive_viewing_key_from_spending(&SK)
		);
		assert_eq!(
			derive_nullifier_key_from_spending(&SK),
			derive_nullifier_key_from_spending(&SK)
		);
		assert_eq!(
			derive_eddsa_key_from_spending(&SK),
			derive_eddsa_key_from_spending(&SK)
		);
	}

	#[test]
	fn different_spending_keys_produce_different_subkeys() {
		assert_ne!(
			derive_viewing_key_from_spending(&[1u8; 32]),
			derive_viewing_key_from_spending(&[2u8; 32])
		);
	}

	#[test]
	fn encryption_key_depends_on_both_inputs() {
		let vk = [1u8; 32];
		let c1 = [2u8; 32];
		let c2 = [3u8; 32];
		assert_ne!(
			derive_encryption_key(&vk, &c1),
			derive_encryption_key(&vk, &c2)
		);
		assert_ne!(
			derive_encryption_key(&[1u8; 32], &c1),
			derive_encryption_key(&[2u8; 32], &c1)
		);
	}

	#[test]
	fn zero_spending_key_produces_non_zero_keys() {
		let sk = [0u8; 32];
		assert_ne!(derive_viewing_key_from_spending(&sk).0, [0u8; 32]);
		assert_ne!(derive_nullifier_key_from_spending(&sk).0, [0u8; 32]);
		assert_ne!(derive_eddsa_key_from_spending(&sk).0, [0u8; 32]);
	}

	// ── KeySet ────────────────────────────────────────────────────────────────

	#[test]
	fn keyset_from_spending_key_matches_standalone_fns() {
		let ks = KeySet::from_spending_key(SK);
		assert_eq!(ks.viewing_key, derive_viewing_key_from_spending(&SK));
		assert_eq!(ks.nullifier_key, derive_nullifier_key_from_spending(&SK));
		assert_eq!(ks.eddsa_key, derive_eddsa_key_from_spending(&SK));
	}

	#[test]
	fn keyset_spending_key_is_private() {
		let ks = KeySet::from_spending_key(SK);
		assert_eq!(ks.spending_key(), &SK);
	}

	#[test]
	fn keyset_export_viewing_key() {
		let ks = KeySet::from_spending_key(SK);
		assert_eq!(ks.export_viewing_key(), ks.viewing_key);
	}

	#[test]
	fn keyset_matches_viewing_key() {
		let ks = KeySet::from_spending_key(SK);
		assert!(ks.matches_viewing_key(&ks.viewing_key));
		assert!(!ks.matches_viewing_key(&ViewingKey([0u8; 32])));
	}
}
