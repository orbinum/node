//! Runtime API implementation for ShieldedPool pallet
//!
//! This module implements the ShieldedPoolRuntimeApi trait defined in the runtime-api crate.
//! These functions are callable from RPC without executing transactions.

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
		let root = crate::infrastructure::repositories::MerkleRepository::get_poseidon_root::<T>();
		let size = crate::infrastructure::repositories::MerkleRepository::get_tree_size::<T>();
		let depth = T::MaxTreeDepth::get();

		(root, size, depth)
	}

	/// Get Merkle proof for a given leaf index
	///
	/// Returns None if:
	/// - Leaf index is out of bounds
	/// - Tree is empty
	pub fn get_merkle_proof(leaf_index: u32) -> Option<DefaultMerklePath> {
		crate::infrastructure::services::merkle_tree_service::MerkleTreeService::get_merkle_path::<T>(
			leaf_index,
		)
	}

	/// Get Merkle proof for a given commitment
	///
	/// This scans all leaves in the tree to find the commitment.
	/// Returns (leaf_index, proof) if found, None otherwise.
	///
	/// Note: This is expensive as it requires scanning all leaves.
	/// Should be used sparingly or cached off-chain.
	pub fn get_merkle_proof_for_commitment(commitment: Hash) -> Option<(u32, DefaultMerklePath)> {
		let commitment_wrapped = Commitment(commitment);

		// Find the leaf index for this commitment
		let leaf_index = crate::infrastructure::services::merkle_tree_service::MerkleTreeService::find_leaf_index::<T>(
			&commitment_wrapped,
		)?;

		// Get the Merkle proof for that index
		let proof = Self::get_merkle_proof(leaf_index)?;

		Some((leaf_index, proof))
	}
}
