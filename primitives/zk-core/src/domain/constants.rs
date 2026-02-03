//! Domain Constants
//!
//! This module contains domain-level constants that represent business rules
//! and invariants of the ZK primitives domain.
//!

//! These constants belong to the **Domain Layer** (inner circle) as they define
//! fundamental domain rules and constraints.
//!

//! - **Merkle Tree**: Tree depth, maximum leaves
//! - **Assets**: Asset ID constraints
//! - **Notes**: Value constraints
//! - **Cryptography**: Field element bounds

/// Maximum depth of the Merkle tree
///
/// This defines the maximum number of levels in the Merkle tree,
/// which determines the maximum number of leaves: 2^MERKLE_TREE_DEPTH.
///
/// ## Domain Rule
/// A depth of 32 allows for 2^32 = 4,294,967,296 notes in the tree,
/// which is sufficient for most shielded pool use cases.
pub const MERKLE_TREE_DEPTH: usize = 32;

/// Maximum number of leaves in the Merkle tree
///
/// Calculated as 2^MERKLE_TREE_DEPTH. This represents the maximum
/// number of commitments (notes) that can be stored in the tree.
///
/// ## Domain Invariant
/// No more than MAX_MERKLE_LEAVES commitments can be inserted.
pub const MAX_MERKLE_LEAVES: u64 = 1 << MERKLE_TREE_DEPTH; // 2^32

/// Default asset ID for native tokens
///
/// Asset ID 0 is reserved for the native token of the blockchain.
///
/// ## Domain Rule
/// - Asset ID 0: Native token (e.g., ETH, DOT)
/// - Asset ID > 0: Registered custom assets
pub const NATIVE_ASSET_ID: u64 = 0;

/// Maximum allowed asset ID
///
/// This sets an upper bound on asset IDs to prevent overflow
/// and ensure efficient storage.
///
/// ## Domain Invariant
/// All asset IDs must be in the range [0, MAX_ASSET_ID].
pub const MAX_ASSET_ID: u64 = u64::MAX;

/// Minimum note value
///
/// Notes with zero value are allowed and used as dummy notes
/// in private transactions for padding.
///
/// ## Domain Rule
/// - Value 0: Allowed (dummy notes)
/// - Value > 0: Real value transfer
pub const MIN_NOTE_VALUE: u64 = 0;

/// Maximum note value
///
/// This is constrained by the field element size and practical
/// token supply considerations.
///
/// ## Domain Invariant
/// All note values must be in the range [MIN_NOTE_VALUE, MAX_NOTE_VALUE].
pub const MAX_NOTE_VALUE: u64 = u64::MAX;

/// Zero field element representation
///
/// This is a convenience constant for the additive identity
/// in the scalar field.
pub const ZERO_FIELD: u64 = 0;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_merkle_tree_depth() {
		assert_eq!(MERKLE_TREE_DEPTH, 32);
	}

	#[test]
	fn test_max_merkle_leaves() {
		// 2^32 = 4,294,967,296
		assert_eq!(MAX_MERKLE_LEAVES, 4_294_967_296);
		assert_eq!(MAX_MERKLE_LEAVES, 1u64 << MERKLE_TREE_DEPTH);
	}

	#[test]
	fn test_native_asset_id() {
		assert_eq!(NATIVE_ASSET_ID, 0);
	}

	#[test]
	fn test_note_value_bounds() {
		assert_eq!(MIN_NOTE_VALUE, 0);
	}

	#[test]
	fn test_zero_field() {
		assert_eq!(ZERO_FIELD, 0);
	}
}
