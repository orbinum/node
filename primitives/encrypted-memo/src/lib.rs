//! Encrypted memo primitives for private transactions with ChaCha20Poly1305 AEAD.
//!
//! # Modules
//!
//! - [`keys`] — Key types (`ViewingKey`, `NullifierKey`, `EdDSAKey`), `KeySet`, derivation fns
//! - [`memo`] — `MemoData`, `MemoError`, encrypt/decrypt functions, size constants
//! - [`value_proof`] — `ValueProofPublicSignals`, `ValueProof` (CircuitId 6)
//!
//! # Example
//!
//! ```rust,ignore
//! use orbinum_encrypted_memo::{MemoData, KeySet, encrypt_memo, decrypt_memo};
//!
//! // Symmetric mode: use viewing_key as shared_secret
//! let keys = KeySet::from_spending_key(spending_key);
//! let memo = MemoData::new(1000, owner_pk, blinding, 0, [0u8; 32]);
//! let encrypted = encrypt_memo(&memo, &commitment, keys.viewing_key.as_bytes(), &nonce)?;
//! let decrypted = decrypt_memo(&encrypted, &commitment, keys.viewing_key.as_bytes())?;
//!
//! // ECDH mode: derive shared_secret externally via BabyJubJub before calling decrypt_memo
//! // let eph_pk = &encrypted[144..176];
//! // let shared_secret = bjj_ecdh(ivsk_scalar, eph_pk);
//! // let decrypted = decrypt_memo(&encrypted, &commitment, &shared_secret)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod keys;
mod memo;
mod value_proof;

// Keys
pub use keys::{
	derive_eddsa_key_from_spending, derive_nullifier_key_from_spending,
	derive_viewing_key_from_spending, EdDSAKey, KeySet, NullifierKey, ViewingKey,
};

// Memo
pub use memo::{
	decrypt_memo, encrypt_memo, is_valid_encrypted_memo, try_decrypt_memo, MemoData, MemoError,
	EPH_PK_SIZE, MAC_SIZE, MAX_ENCRYPTED_MEMO_SIZE, MEMO_DATA_SIZE, MIN_ENCRYPTED_MEMO_SIZE,
	NONCE_SIZE,
};

#[cfg(feature = "encrypt")]
pub use memo::encrypt_memo_random;

// Value proof
pub use value_proof::{ValueProof, ValueProofPublicSignals};
