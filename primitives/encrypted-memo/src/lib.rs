//! Encrypted memo primitives for private transactions with ChaCha20Poly1305 AEAD
//!
//! ## Features
//!
//! - **Encryption**: Per-note key derivation from viewing key + commitment
//! - **Disclosure**: Selective disclosure proof structures (Groth16)
//! - **Key Derivation**: SHA-256 based with domain separation
//!
//! ## Architecture
//!
//! Clean Architecture — domain layer only, no FRAME dependencies:
//! - **value_objects**: Immutable keys and constants
//! - **entities**: `MemoData` entity + `MemoError`
//! - **ports**: Abstract interfaces (`MemoEncryptor`, `KeyDeriver`)
//! - **aggregates**: `KeySet`, disclosure structures
//! - **services**: Concrete implementations of the ports
//!
//! ## Example
//!
//! ```rust,ignore
//! use fp_encrypted_memo::{MemoData, KeySet, encrypt_memo, decrypt_memo};
//!
//! let keys = KeySet::from_spending_key(spending_key);
//! let memo = MemoData::new(1000, owner_pk, blinding, 0);
//! let encrypted = encrypt_memo(&memo, &commitment, keys.viewing_key.as_bytes(), &nonce)?;
//! let decrypted = decrypt_memo(&encrypted, &commitment, keys.viewing_key.as_bytes())?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ============================================================================
// Modules
// ============================================================================

// Domain layer - pure business logic
pub mod domain;

// ============================================================================
// Public API
// ============================================================================

// Constants
pub use domain::value_objects::constants::{
	EDDSA_KEY_DOMAIN, KEY_DOMAIN, MAC_SIZE, MAX_ENCRYPTED_MEMO_SIZE, MEMO_DATA_SIZE,
	MIN_ENCRYPTED_MEMO_SIZE, NONCE_SIZE, NULLIFIER_KEY_DOMAIN, VIEWING_KEY_DOMAIN,
};

// Value objects (keys)
pub use domain::value_objects::{EdDSAKey, NullifierKey, ViewingKey};

// Core entity and error
pub use domain::entities::{error::MemoError, is_valid_encrypted_memo, memo_data::MemoData};

// Key set aggregate
pub use domain::aggregates::keyset::KeySet;

// Disclosure aggregates
pub use domain::aggregates::disclosure::{
	DisclosureMask, DisclosureProof, DisclosurePublicSignals, PartialMemoData,
};

// Ports (abstract interfaces)
pub use domain::ports::{KeyDeriver, MemoEncryptor};

// Encryption services
pub use domain::services::encryption::{decrypt_memo, encrypt_memo, try_decrypt_memo};

#[cfg(feature = "encrypt")]
pub use domain::services::encryption::encrypt_memo_random;

// Key derivation services
pub use domain::services::key_derivation::{
	derive_eddsa_key_from_spending, derive_nullifier_key_from_spending,
	derive_viewing_key_from_spending,
};
