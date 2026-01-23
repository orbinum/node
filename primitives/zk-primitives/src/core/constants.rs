//! # Constants
//!
//! Global constants for zero-knowledge primitives.

// ============================================================================
// Merkle Tree
// ============================================================================

/// Default Merkle tree depth (20 levels = ~1 million leaves)
pub const DEFAULT_TREE_DEPTH: usize = 20;

/// Maximum supported Merkle tree depth
pub const MAX_TREE_DEPTH: usize = 32;

// ============================================================================
// Assets
// ============================================================================

/// Default asset ID for the native token
pub const NATIVE_ASSET_ID: u64 = 0;

// ============================================================================
// Serialization
// ============================================================================

/// Field element size in bytes
pub const FIELD_ELEMENT_SIZE: usize = 32;

// ============================================================================
// Domain Separators
// ============================================================================

/// Domain separator for commitment computations
pub const COMMITMENT_DOMAIN: &str = "orbinum-commitment-v1";

/// Domain separator for nullifier computations
pub const NULLIFIER_DOMAIN: &str = "orbinum-nullifier-v1";
