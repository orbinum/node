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
