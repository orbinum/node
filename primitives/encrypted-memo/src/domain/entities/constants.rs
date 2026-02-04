//! Constants
//!
//! Size constraints and domain separators for encrypted memo operations.

/// Maximum encrypted memo size in bytes
///
/// Layout: `nonce(12) + note_data(76) + MAC(16) = 104`
pub const MAX_ENCRYPTED_MEMO_SIZE: usize = 104;

/// Minimum encrypted memo size in bytes
///
/// Layout: `nonce(12) + MAC(16) = 28`
pub const MIN_ENCRYPTED_MEMO_SIZE: usize = 12 + 16;

/// Plaintext memo data size (before encryption)
pub const MEMO_DATA_SIZE: usize = 76;

/// Size of ChaCha20Poly1305 nonce
pub const NONCE_SIZE: usize = 12;

/// Size of ChaCha20Poly1305 authentication tag
pub const MAC_SIZE: usize = 16;

/// Domain separator for key derivation
pub const KEY_DOMAIN: &[u8] = b"orbinum-note-encryption-v1";
