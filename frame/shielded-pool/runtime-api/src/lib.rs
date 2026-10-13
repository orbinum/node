#![cfg_attr(not(feature = "std"), no_std)]

use pallet_shielded_pool::{DefaultMerklePath, Hash, SubtreeRoots};

sp_api::decl_runtime_apis! {
	#[api_version(5)]
	pub trait ShieldedPoolRuntimeApi {
		/// Get the Merkle tree information (root, size, depth)
		fn get_merkle_tree_info() -> (Hash, u32, u32);

		/// Get the Merkle proof for a given leaf index
		fn get_merkle_proof(leaf_index: u32) -> Option<DefaultMerklePath>;

		/// Get the Merkle proof for a given commitment.
		/// O(1) index lookup plus O(depth) sibling reads from stored nodes.
		fn get_merkle_proof_for_commitment(commitment: Hash) -> Option<(u32, DefaultMerklePath)>;

		/// Forest summary: (active_root, global_size, depth, current_tree_id,
		/// sealed_tree_count).
		fn get_forest_info() -> (Hash, u32, u32, u32, u32);

		/// Root the given leaf's tree anchors to, plus its tree_id: the
		/// permanent sealed root for completed trees, the live PoseidonRoot
		/// for the active tree. None if the leaf does not exist.
		fn get_root_for_leaf(leaf_index: u32) -> Option<(Hash, u32)>;

		/// Up to `count` level-6 subtree roots of `tree_id` from `start`, with the
		/// root the tree anchors to, read from one state, so a wallet can build
		/// its own Merkle paths. None for a tree that does not exist yet.
		fn get_subtree_roots(tree_id: u32, start: u32, count: u32) -> Option<SubtreeRoots>;
	}
}
