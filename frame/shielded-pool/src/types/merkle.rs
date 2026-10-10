//! Merkle path type and the tree-depth constants.
//!
//! `DEFAULT_TREE_DEPTH` is fixed at 20 and pinned by `integrity_test`: clients
//! derive a note's `tree_id` from it, so changing it on a live chain would
//! re-map every existing note.

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

// MerklePath

pub const DEFAULT_TREE_DEPTH: usize = 20;
pub const MAX_TREE_DEPTH: u32 = 20;

/// A Merkle path (siblings from leaf to root).
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct MerklePath<const DEPTH: usize> {
	pub siblings: [[u8; 32]; DEPTH],
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

pub type DefaultMerklePath = MerklePath<DEFAULT_TREE_DEPTH>;

/// Level of the subtree roots a wallet reads to build its own paths: each covers
/// a block of `2^SUBTREE_LEVEL` = 64 leaves.
pub const SUBTREE_LEVEL: u8 = 6;

/// Subtree roots served per call, at most: a quarter of a full tree's 2^14.
pub const MAX_SUBTREE_ROOTS: u32 = 4096;

/// The level-[`SUBTREE_LEVEL`] roots of one tree, read from one state.
///
/// A wallet folds them into the upper 14 levels of its path, and its note's
/// block from leaves it scanned into the lower 6. Every root but the last of an
/// active tree is final: a block's leaves never change once it is full.
#[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq, Eq)]
pub struct SubtreeRoots {
	pub tree_id: u32,
	/// Leaves in this tree: the capacity once sealed.
	pub tree_leaves: u32,
	pub sealed: bool,
	/// The root the tree anchors to: its final root once sealed, else the live
	/// root, at the state the subtree roots were read at.
	pub root: [u8; 32],
	/// Index of `roots[0]` within the level.
	pub start: u32,
	pub roots: sp_std::vec::Vec<[u8; 32]>,
}
