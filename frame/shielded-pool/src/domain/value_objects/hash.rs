//! Hash value object
//!
//! A 32-byte hash type used throughout the shielded pool for Merkle roots,
//! commitments, nullifiers, and other cryptographic hashes.

/// A 32-byte hash type
///
/// Used for:
/// - Merkle tree roots
/// - Cryptographic hashes
/// - Identifiers
pub type Hash = [u8; 32];
