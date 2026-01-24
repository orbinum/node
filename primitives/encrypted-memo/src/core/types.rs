//! Core types for encrypted memos
//!
//! This module provides the fundamental types used in memo encryption:
//! - MemoData: Plaintext memo structure
//! - ViewingKey: Key for decrypting memos
//! - NullifierKey: Key for deriving nullifiers
//! - EdDSAKey: Key for circuit ownership proofs

use super::error::MemoError;
#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;

/// Plaintext memo data (before encryption)
///
/// This contains the essential information needed to reconstruct a note.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct MemoData {
	/// The value/amount in the note
	pub value: u64,
	/// Owner's public key (32 bytes)
	pub owner_pk: [u8; 32],
	/// Random blinding factor (32 bytes)
	pub blinding: [u8; 32],
	/// Asset identifier (0 = native token)
	pub asset_id: u32,
}

impl MemoData {
	/// Create new memo data
	pub fn new(value: u64, owner_pk: [u8; 32], blinding: [u8; 32], asset_id: u32) -> Self {
		Self {
			value,
			owner_pk,
			blinding,
			asset_id,
		}
	}

	/// Serialize memo data to bytes (76 bytes total)
	///
	/// Format:
	/// - value: u64 (8 bytes, little-endian)
	/// - owner_pk: [u8; 32] (32 bytes)
	/// - blinding: [u8; 32] (32 bytes)
	/// - asset_id: u32 (4 bytes, little-endian)
	pub fn to_bytes(&self) -> [u8; 76] {
		let mut bytes = [0u8; 76];
		bytes[0..8].copy_from_slice(&self.value.to_le_bytes());
		bytes[8..40].copy_from_slice(&self.owner_pk);
		bytes[40..72].copy_from_slice(&self.blinding);
		bytes[72..76].copy_from_slice(&self.asset_id.to_le_bytes());
		bytes
	}

	/// Deserialize memo data from bytes
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() != 76 {
			return Err(MemoError::InvalidNoteData);
		}

		let value = u64::from_le_bytes(
			bytes[0..8]
				.try_into()
				.map_err(|_| MemoError::InvalidNoteData)?,
		);

		let mut owner_pk = [0u8; 32];
		owner_pk.copy_from_slice(&bytes[8..40]);

		let mut blinding = [0u8; 32];
		blinding.copy_from_slice(&bytes[40..72]);

		let asset_id = u32::from_le_bytes(
			bytes[72..76]
				.try_into()
				.map_err(|_| MemoError::InvalidNoteData)?,
		);

		Ok(Self {
			value,
			owner_pk,
			blinding,
			asset_id,
		})
	}
}

/// Viewing key for memo decryption
///
/// This key allows decrypting transaction memos to view:
/// - Received amounts
/// - Note blinding factors
/// - Transaction history
///
/// ## Security Properties
///
/// - **Read-only**: Cannot spend funds (requires spending key)
/// - **Shareable**: Can be given to auditors for read-only access
/// - **Domain-separated**: Cannot be confused with spending key
///
/// ## Derivation
///
/// ```text
/// viewing_key = SHA256(spending_key || "orbinum-viewing-key-v1")
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct ViewingKey(pub [u8; 32]);

impl ViewingKey {
	/// Create viewing key from raw bytes
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Get raw bytes
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// Derive viewing key from spending key
	///
	/// Uses SHA-256 with domain separation:
	/// `viewing_key = SHA256(spending_key || "orbinum-viewing-key-v1")`
	pub fn from_spending_key(spending_key: &[u8; 32]) -> Self {
		crate::crypto::key_derivation::derive_viewing_key_from_spending(spending_key)
	}

	/// Try to decrypt a memo using this viewing key
	///
	/// Returns `Some(MemoData)` if decryption succeeds (note belongs to this key).
	/// Returns `None` if decryption fails (note doesn't belong to us).
	pub fn try_decrypt(&self, encrypted: &[u8], commitment: &[u8; 32]) -> Option<MemoData> {
		crate::crypto::encryption::try_decrypt_memo(encrypted, commitment, &self.0)
	}

	/// Decrypt a memo using this viewing key
	pub fn decrypt(&self, encrypted: &[u8], commitment: &[u8; 32]) -> Result<MemoData, crate::core::error::MemoError> {
		crate::crypto::encryption::decrypt_memo(encrypted, commitment, &self.0)
	}
}

impl AsRef<[u8; 32]> for ViewingKey {
	fn as_ref(&self) -> &[u8; 32] {
		&self.0
	}
}

impl From<[u8; 32]> for ViewingKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
}

/// Nullifier derivation key
///
/// Used internally to derive nullifiers for spent notes.
/// This key is separate from viewing and spending keys.
///
/// ## Security
///
/// - Nullifier key alone cannot spend or view funds
/// - Required together with note data to compute nullifiers
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct NullifierKey(pub [u8; 32]);

impl NullifierKey {
	/// Create nullifier key from raw bytes
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Get raw bytes
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// Derive nullifier key from spending key
	///
	/// Uses SHA-256 with domain separation:
	/// `nullifier_key = SHA256(spending_key || "orbinum-nullifier-key-v1")`
	pub fn from_spending_key(spending_key: &[u8; 32]) -> Self {
		crate::crypto::key_derivation::derive_nullifier_key_from_spending(spending_key)
	}
}

impl AsRef<[u8; 32]> for NullifierKey {
	fn as_ref(&self) -> &[u8; 32] {
		&self.0
	}
}

impl From<[u8; 32]> for NullifierKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
}

/// EdDSA signing key for circuit ownership proofs
///
/// This key is used to sign note commitments in the ZK circuit,
/// proving ownership without revealing the spending key.
///
/// ## Security
///
/// - EdDSA key alone cannot spend funds (requires spending key for nullifiers)
/// - Derived deterministically from spending key
/// - Uses BabyJubJub curve (compatible with circom circuits)
/// - Domain-separated to prevent key confusion
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct EdDSAKey(pub [u8; 32]);

impl EdDSAKey {
	/// Create EdDSA key from raw bytes
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Get raw bytes
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// Derive EdDSA key from spending key
	///
	/// Uses SHA-256 with domain separation:
	/// `eddsa_key = SHA256(spending_key || "orbinum-eddsa-key-v1")`
	pub fn from_spending_key(spending_key: &[u8; 32]) -> Self {
		crate::crypto::key_derivation::derive_eddsa_key_from_spending(spending_key)
	}
}

impl AsRef<[u8; 32]> for EdDSAKey {
	fn as_ref(&self) -> &[u8; 32] {
		&self.0
	}
}

impl From<[u8; 32]> for EdDSAKey {
	fn from(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
}
