//! Encrypted memo primitives for private transactions with ChaCha20Poly1305 AEAD.
//!
//! # Modules
//!
//! - [`keys`] — Key types (`ViewingKey`, `NullifierKey`, `EdDSAKey`), `KeySet`, derivation fns
//! - [`memo`] — `MemoData`, `MemoError`, encrypt/decrypt functions, size constants
//! - [`disclosure`] — `DisclosureMask`, `DisclosurePublicSignals`, `DisclosureProof`, `PartialMemoData`
//!
//! # Example
//!
//! ```rust,ignore
//! use orbinum_encrypted_memo::{MemoData, KeySet, encrypt_memo, decrypt_memo};
//!
//! let keys = KeySet::from_spending_key(spending_key);
//! let memo = MemoData::new(1000, owner_pk, blinding, 0, [0u8; 32]);
//! let encrypted = encrypt_memo(&memo, &commitment, keys.viewing_key.as_bytes(), &nonce)?;
//! let decrypted = decrypt_memo(&encrypted, &commitment, keys.viewing_key.as_bytes())?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod disclosure;
mod keys;
mod memo;

// Keys
pub use keys::{
	derive_eddsa_key_from_spending, derive_nullifier_key_from_spending,
	derive_viewing_key_from_spending, EdDSAKey, KeySet, NullifierKey, ViewingKey,
};

// Memo
pub use memo::{
	decrypt_memo, encrypt_memo, is_valid_encrypted_memo, try_decrypt_memo, MemoData, MemoError,
	MAC_SIZE, MAX_ENCRYPTED_MEMO_SIZE, MEMO_DATA_SIZE, MIN_ENCRYPTED_MEMO_SIZE, NONCE_SIZE,
};

#[cfg(feature = "encrypt")]
pub use memo::encrypt_memo_random;

// Disclosure
pub use disclosure::{DisclosureMask, DisclosureProof, DisclosurePublicSignals, PartialMemoData};
