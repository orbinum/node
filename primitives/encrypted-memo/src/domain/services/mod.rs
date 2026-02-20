//! Domain Services
//!
//! Business logic services implementing the ports defined in `domain::ports`.
//!
//! ## Services
//!
//! - [`encryption`]    - ChaCha20Poly1305 AEAD encryption/decryption
//! - [`key_derivation`] - SHA-256 key derivation with domain separation

pub mod encryption;
pub mod key_derivation;
