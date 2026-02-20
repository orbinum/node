//! Ports (interfaces)
//!
//! Traits defining the boundaries of the domain. Infrastructure adapters
//! implement these traits; the domain only depends on them.
//!
//! ## Ports
//!
//! - [`memo_encryptor`] - ChaCha20Poly1305 encryption contract
//! - [`key_deriver`]    - SHA-256 key derivation contract

pub mod key_deriver;
pub mod memo_encryptor;

pub use key_deriver::KeyDeriver;
pub use memo_encryptor::MemoEncryptor;
