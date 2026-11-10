//! The `ShieldedPoolRuntimeApi` queries (defined in the runtime-api crate):
//! read-only views of the tree and the forest, callable from RPC.

use crate::{Commitment, DefaultMerklePath, Hash, Pallet, pallet::Config};
use frame_support::traits::Get;

impl<T: Config> Pallet<T> {
	/// Get Merkle tree information (root, size, depth)
	///
	/// Returns:
	/// - Current Merkle root
	/// - Current tree size (number of leaves)
	/// - Maximum tree depth
	pub fn get_merkle_tree_info() -> (Hash, u32, u32) {
		let root = crate::storage::MerkleRepository::get_poseidon_root::<T>();
		let size = crate::storage::MerkleRepository::get_tree_size::<T>();
		let depth = T::MaxTreeDepth::get();

		(root, size, depth)
	}

	/// Get Merkle proof for a given leaf index
	///
	/// Returns None if:
	/// - Leaf index is out of bounds
	/// - Tree is empty
	pub fn get_merkle_proof(leaf_index: u32) -> Option<DefaultMerklePath> {
		crate::merkle::MerkleTreeService::get_merkle_path::<T>(leaf_index)
	}

	/// Forest summary: (active_root, global_size, depth, current_tree_id,
	/// sealed_tree_count).
	pub fn get_forest_info() -> (Hash, u32, u32, u32, u32) {
		let root = crate::storage::MerkleRepository::get_poseidon_root::<T>();
		let size = crate::storage::MerkleRepository::get_tree_size::<T>();
		let cap = T::MaxLeavesPerTree::get();
		(root, size, T::MaxTreeDepth::get(), size / cap, size / cap)
	}

	/// Root the leaf's tree anchors to: sealed trees resolve to their
	/// permanent final root, the active tree to the live PoseidonRoot.
	pub fn get_root_for_leaf(leaf_index: u32) -> Option<(Hash, u32)> {
		let size = crate::storage::MerkleRepository::get_tree_size::<T>();
		if leaf_index >= size {
			return None;
		}
		let cap = T::MaxLeavesPerTree::get();
		let tree_id = leaf_index / cap;
		let root = if tree_id == size / cap {
			crate::storage::MerkleRepository::get_poseidon_root::<T>()
		} else {
			crate::storage::MerkleRepository::get_sealed_root::<T>(tree_id)?
		};
		Some((root, tree_id))
	}

	/// Level-6 subtree roots of `tree_id` from `start`, with its anchoring root.
	pub fn get_subtree_roots(tree_id: u32, start: u32, count: u32) -> Option<crate::SubtreeRoots> {
		crate::merkle::MerkleTreeService::get_subtree_roots::<T>(tree_id, start, count)
	}

	/// Get Merkle proof for a given commitment.
	///
	/// O(1) reverse-index lookup plus an O(depth) sibling-path read from
	/// `MerkleNodes`. Returns (leaf_index, proof) if found, None otherwise.
	pub fn get_merkle_proof_for_commitment(commitment: Hash) -> Option<(u32, DefaultMerklePath)> {
		let commitment_wrapped = Commitment(commitment);

		// Find the leaf index for this commitment
		let leaf_index =
			crate::merkle::MerkleTreeService::find_leaf_index::<T>(&commitment_wrapped)?;

		// Get the Merkle proof for that index
		let proof = Self::get_merkle_proof(leaf_index)?;

		Some((leaf_index, proof))
	}
}
