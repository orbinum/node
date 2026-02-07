//! Merkle path type for tree proofs
//!
//! This module defines the MerklePath type used to prove inclusion
//! of a commitment in the Merkle tree.

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Default Merkle tree depth (supports 2^20 = 1,048,576 commitments)
pub const DEFAULT_TREE_DEPTH: usize = 20;

/// Maximum depth of Merkle tree (supports 2^20 = ~1M leaves)
pub const MAX_TREE_DEPTH: u32 = 20;

/// A Merkle path (siblings from leaf to root)
///
/// A Merkle path consists of sibling hashes along the path from a leaf
/// to the root, allowing verification of a leaf's inclusion in the tree.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct MerklePath<const DEPTH: usize> {
	/// Sibling hashes from leaf to root
	pub siblings: [[u8; 32]; DEPTH],
	/// Path indices (0 = left, 1 = right) - indicates position of the leaf
	pub indices: [u8; DEPTH],
}

impl<const DEPTH: usize> Default for MerklePath<DEPTH> {
	fn default() -> Self {
		Self {
			siblings: [[0u8; 32]; DEPTH],
			indices: [0u8; DEPTH],
		}
	}
}

/// MerklePath with default depth
pub type DefaultMerklePath = MerklePath<DEFAULT_TREE_DEPTH>;
