//! # Encrypted Memo Primitives
//!
//! This crate provides encryption and decryption utilities for private transaction memos.
//!
//! ## Overview
//!
//! When transferring private assets, the sender encrypts note details (value, blinding, etc.)
//! using the recipient's viewing key. This allows the recipient to:
//!
//! 1. Scan blockchain events for notes they own
//! 2. Decrypt and recover note details
//! 3. Spend the received funds
//!
//! ## Encryption Scheme
//!
//! The encryption uses a symmetric key derived from the viewing key:
//!
//! ```text
//! encryption_key = SHA256(viewing_key || commitment || "orbinum-note-encryption-v1")
//! ciphertext = ChaCha20Poly1305(note_data, encryption_key, random_nonce)
//! encrypted_memo = nonce (12 bytes) || ciphertext (76 bytes + 16 bytes MAC)
//! ```
//!
//! ## Security Properties
//!
//! - **Confidentiality**: Only the recipient can decrypt (requires viewing key)
//! - **Authenticity**: ChaCha20Poly1305 provides AEAD (tampering detected)
//! - **Unlinkability**: Each memo uses unique key derived from commitment
//!
//! ## Architecture (3 Layers)
//!
//! - **Layer 1: Core** ([`core`]) - Fundamental types, constants, and errors
//!   - [`core::types`] - MemoData, ViewingKey, NullifierKey, EdDSAKey
//!   - [`core::constants`] - Size and domain separator constants
//!   - [`core::error`] - Error types
//!
//! - **Layer 2: Crypto** ([`crypto`]) - Cryptographic operations
//!   - [`crypto::encryption`] - ChaCha20Poly1305 encrypt/decrypt
//!   - [`crypto::key_derivation`] - Key derivation functions
//!   - [`crypto::validation`] - Validation utilities
//!
//! - **Layer 3: Models** ([`models`]) - High-level abstractions
//!   - [`models::keyset`] - KeySet management
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_encrypted_memo::{
//!     MemoData, KeySet,
//!     crypto::encryption::{encrypt_memo, decrypt_memo},
//! };
//!
//! // Derive keys
//! let keys = KeySet::from_spending_key(spending_key);
//!
//! // Encrypt (sender side)
//! let memo_data = MemoData::new(1000, owner_pk, blinding, 0);
//! let encrypted = encrypt_memo(&memo_data, &commitment, &recipient_vk, &nonce)?;
//!
//! // Decrypt (recipient side)
//! let decrypted = keys.decrypt(&encrypted, &commitment)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ============================================================================
// Modules (3-Layer Architecture)
// ============================================================================

/// Layer 1: Core types, constants, and errors
pub mod core;

/// Layer 2: Cryptographic operations
pub mod crypto;

/// Layer 3: High-level abstractions
pub mod models;

// ============================================================================
// Public Re-exports
// ============================================================================

// Core types (most commonly used)
pub use core::error::MemoError;
pub use core::types::{EdDSAKey, MemoData, NullifierKey, ViewingKey};

// Constants
pub use core::constants::{
	KEY_DOMAIN, MAC_SIZE, MAX_ENCRYPTED_MEMO_SIZE, MEMO_DATA_SIZE, MIN_ENCRYPTED_MEMO_SIZE,
	NONCE_SIZE,
};

// Crypto operations (convenience re-exports)
pub use crypto::encryption::{decrypt_memo, encrypt_memo, try_decrypt_memo};
#[cfg(feature = "encrypt")]
pub use crypto::encryption::encrypt_memo_random;
pub use crypto::key_derivation::{derive_eddsa_key, derive_nullifier_key, derive_viewing_key};
pub use crypto::validation::is_valid_encrypted_memo;

// Models
pub use models::keyset::KeySet;

