//! Domain Services
//!
//! Pure business logic services without external dependencies.
//!
//! ## Services
//!
//! - [`encryption`] - ChaCha20Poly1305 AEAD encryption/decryption
//! - [`key_derivation`] - SHA-256 key derivation with domain separation
//! - [`validation`] - Format validation utilities

pub mod encryption;
pub mod key_derivation;
pub mod validation;
