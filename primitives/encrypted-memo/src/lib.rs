//! Encrypted memo primitives for private transactions with ChaCha20Poly1305 AEAD
//!
//! ## Features
//!
//! - **Encryption**: Per-note key derivation from viewing key + commitment
//! - **Disclosure**: Selective ZK proof generation (Groth16)
//! - **Key Derivation**: SHA-256 based with domain separation
//!
//! ## Architecture
//!
//! Clean Architecture in 3 layers:
//! - **Domain**: Pure business logic (entities, aggregates, services)
//! - **Application**: Use cases (disclosure proofs, WASM witness)
//! - **Infrastructure**: External adapters (JSON, key validation, WASM)
//!
//! ## Example
//!
//! ```rust,ignore
//! use fp_encrypted_memo::{MemoData, KeySet, encrypt_memo, decrypt_memo};
//!
//! let keys = KeySet::from_spending_key(&spending_key);
//! let memo = MemoData::new(1000, owner_pk, blinding, 0);
//! let encrypted = encrypt_memo(&memo, &commitment, &recipient_vk)?;
//! let decrypted = decrypt_memo(&encrypted, &commitment, &keys.viewing_key)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ============================================================================
// Modules
// ============================================================================

/// Domain layer - Pure business logic
pub mod domain;

/// Application layer - Use cases
pub mod application;

/// Infrastructure layer - External adapters
pub mod infrastructure;

// ============================================================================
// Public API
// ============================================================================

// Core types
pub use domain::entities::{
	constants::{
		KEY_DOMAIN, MAC_SIZE, MAX_ENCRYPTED_MEMO_SIZE, MEMO_DATA_SIZE, MIN_ENCRYPTED_MEMO_SIZE,
		NONCE_SIZE,
	},
	error::MemoError,
	types::{EdDSAKey, MemoData, NullifierKey, ViewingKey},
};

// Aggregates
pub use domain::aggregates::keyset::KeySet;

// Encryption services
pub use domain::services::encryption::{decrypt_memo, encrypt_memo, try_decrypt_memo};

// Note: encrypt_memo already generates random nonces automatically
// No separate encrypt_memo_random function needed
// #[cfg(feature = "encrypt")]
// pub use domain::services::encryption::encrypt_memo_random;

// Key derivation services
pub use domain::services::key_derivation::{
	derive_eddsa_key, derive_nullifier_key, derive_viewing_key,
};

// Validation services
pub use domain::services::validation::is_valid_encrypted_memo;

// Disclosure feature
#[cfg(feature = "disclosure")]
pub use domain::aggregates::disclosure::{
	DisclosureMask, DisclosureProof, DisclosurePublicSignals, PartialMemoData,
};

#[cfg(feature = "disclosure")]
pub use application::disclosure::generate_disclosure_proof;

// ============================================================================
// Infrastructure Utilities (Optional)
// ============================================================================

/// Proving key validation (caller must load files, no I/O)
#[cfg(all(feature = "disclosure", feature = "std"))]
pub mod key_loader {
	pub use crate::infrastructure::repositories::key_loader::{
		calculate_key_checksum, detect_key_format, print_key_info, validate_proving_key,
		verify_key_checksum,
	};
}
