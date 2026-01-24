//! Memo constants
//!
//! Size and domain separator constants for encrypted memos.

/// Maximum size of encrypted memo in bytes
/// Layout: 12 (nonce) + 76 (note data) + 16 (MAC) = 104 bytes
pub const MAX_ENCRYPTED_MEMO_SIZE: usize = 104;

/// Minimum size (nonce + empty ciphertext + MAC)
pub const MIN_ENCRYPTED_MEMO_SIZE: usize = 12 + 16;

/// Size of plaintext memo data (before encryption)
pub const MEMO_DATA_SIZE: usize = 76;

/// Size of ChaCha20Poly1305 nonce
pub const NONCE_SIZE: usize = 12;

/// Size of ChaCha20Poly1305 authentication tag
pub const MAC_SIZE: usize = 16;

/// Domain separator for key derivation
pub const KEY_DOMAIN: &[u8] = b"orbinum-note-encryption-v1";
