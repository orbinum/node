//! Merkle Tree Service - Manages Merkle tree operations

use crate::{
	domain::Commitment,
	domain::value_objects::{DefaultMerklePath, Hash},
	infrastructure::repositories::MerkleRepository,
	pallet::{Config, Error, Event, Pallet},
};
use frame_support::{ensure, pallet_prelude::*, traits::Get};

pub struct MerkleTreeService;

impl MerkleTreeService {
	/// Insert a new leaf into the Merkle tree
	pub fn insert_leaf<T: Config>(commitment: Commitment) -> Result<u32, DispatchError> {
		let index = MerkleRepository::get_tree_size::<T>();
		let max_leaves = 2u32.saturating_pow(T::MaxTreeDepth::get());

		ensure!(index < max_leaves, Error::<T>::MerkleTreeFull);

		// Store the leaf using repository
		MerkleRepository::insert_leaf::<T>(index, commitment);

		// Increment tree size BEFORE computing roots (needed for get_all_leaves)
		MerkleRepository::set_tree_size::<T>(index.saturating_add(1));

		// Update Poseidon root (only system used now)
		let new_poseidon_root = Self::compute_poseidon_merkle_root::<T>();
		MerkleRepository::set_poseidon_root::<T>(new_poseidon_root);

		// Add to historic roots with pruning if necessary
		Self::add_poseidon_historic_root::<T>(new_poseidon_root);

		// Emit root update event
		Pallet::<T>::deposit_event(Event::MerkleRootUpdated {
			old_root: [0u8; 32], // Not tracking old root anymore
			new_root: new_poseidon_root,
			tree_size: index.saturating_add(1),
		});

		Ok(index)
	}

	/// Compute Poseidon Merkle root (primary system)
	fn compute_poseidon_merkle_root<T: Config>() -> Hash {
		let leaves = MerkleRepository::get_all_leaves::<T>();

		if leaves.is_empty() {
			return [0u8; 32];
		}

		// Compute with Poseidon
		crate::infrastructure::merkle_tree::compute_root_from_leaves_poseidon::<20>(&leaves)
	}

	/// Add a Poseidon historic root with FIFO pruning
	fn add_poseidon_historic_root<T: Config>(poseidon_root: Hash) {
		// Get current order list using repository
		let mut order = MerkleRepository::get_historic_roots_order::<T>();

		// Check if we need to prune the oldest root
		if order.len() >= T::MaxHistoricRoots::get() as usize {
			// Remove the oldest root (first in the list)
			if let Some(oldest_root) = order.first().copied() {
				// Remove from Poseidon historic roots
				MerkleRepository::remove_poseidon_historic_root::<T>(&oldest_root);
				// Remove from order list
				order.remove(0);
			}
		}

		// Add the new Poseidon root
		MerkleRepository::add_historic_poseidon_root::<T>(poseidon_root);

		// Try to add to order list (should always succeed after pruning)
		let _ = order.try_push(poseidon_root);

		// Update storage using repository
		MerkleRepository::set_historic_roots_order::<T>(order);
	}

	/// Check if a Merkle root is known
	pub fn is_known_root<T: Config>(root: &Hash) -> bool {
		MerkleRepository::is_known_root::<T>(root)
	}

	/// Get the Merkle path for a leaf (for generating proofs off-chain)
	pub fn get_merkle_path<T: Config>(leaf_index: u32) -> Option<DefaultMerklePath> {
		let size = MerkleRepository::get_tree_size::<T>();
		if leaf_index >= size {
			return None;
		}

		// Collect all leaves using repository
		let leaves = MerkleRepository::get_all_leaves::<T>();

		if leaves.is_empty() {
			return None;
		}

		// Build the Merkle path by computing siblings
		let mut siblings = [[0u8; 32]; 20];
		let mut indices = [0u8; 20];
		let mut index = leaf_index as usize;

		// For each level, compute the sibling
		for level in 0..20 {
			let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

			// Determine if we're on the left (0) or right (1)
			indices[level] = (index % 2) as u8;

			// Get the sibling hash
			if sibling_index < leaves.len() {
				siblings[level] = leaves[sibling_index];
			} else {
				// Use zero hash if sibling doesn't exist
				siblings[level] = crate::infrastructure::merkle_tree::zero_hash_at_level(level);
			}

			// Move to parent level
			index /= 2;
		}

		Some(DefaultMerklePath { siblings, indices })
	}

	/// Verify a Merkle proof for a given leaf
	pub fn verify_merkle_proof(root: &Hash, leaf: &Hash, path: &DefaultMerklePath) -> bool {
		// Use the path directly - it's already compatible with the verification
		crate::infrastructure::merkle_tree::IncrementalMerkleTree::<20>::verify_proof(
			root, leaf, path,
		)
	}

	/// Find leaf index for a commitment (Linear scan - expensive, only for RPC)
	pub fn find_leaf_index<T: Config>(commitment: &Commitment) -> Option<u32> {
		crate::infrastructure::repositories::MerkleRepository::find_leaf_index::<T>(commitment)
	}
}
