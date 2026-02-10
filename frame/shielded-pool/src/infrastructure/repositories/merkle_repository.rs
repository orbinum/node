//! Merkle Repository - Encapsulates Merkle tree storage access

use crate::{
	domain::Commitment,
	domain::value_objects::Hash,
	pallet::{
		Config, HistoricPoseidonRoots, HistoricRootsOrder, MerkleLeaves, MerkleTreeSize,
		PoseidonRoot,
	},
};
use frame_support::pallet_prelude::*;

/// Repository for Merkle tree storage operations
pub struct MerkleRepository;

impl MerkleRepository {
	/// Get current Poseidon Merkle root
	pub fn get_poseidon_root<T: Config>() -> Hash {
		PoseidonRoot::<T>::get()
	}

	/// Set new Poseidon Merkle root
	pub fn set_poseidon_root<T: Config>(root: Hash) {
		PoseidonRoot::<T>::put(root);
	}

	/// Get current tree size
	pub fn get_tree_size<T: Config>() -> u32 {
		MerkleTreeSize::<T>::get()
	}

	/// Set tree size
	pub fn set_tree_size<T: Config>(size: u32) {
		MerkleTreeSize::<T>::put(size);
	}

	/// Get leaf at index
	pub fn get_leaf<T: Config>(index: u32) -> Option<Commitment> {
		MerkleLeaves::<T>::get(index)
	}

	/// Insert leaf at index
	pub fn insert_leaf<T: Config>(index: u32, commitment: Commitment) {
		MerkleLeaves::<T>::insert(index, commitment);
	}

	/// Check if Poseidon root is known (historic or current)
	pub fn is_known_poseidon_root<T: Config>(root: &Hash) -> bool {
		HistoricPoseidonRoots::<T>::get(root)
	}

	/// Check if root is known (Poseidon only)
	pub fn is_known_root<T: Config>(root: &Hash) -> bool {
		// Only check Poseidon roots (Blake2 legacy removed)
		Self::is_known_poseidon_root::<T>(root)
	}

	/// Add Poseidon root to historic roots (Poseidon-only system)
	pub fn add_historic_poseidon_root<T: Config>(root: Hash) {
		HistoricPoseidonRoots::<T>::insert(root, true);
	}

	/// Remove Poseidon root from historic roots
	pub fn remove_poseidon_historic_root<T: Config>(root: &Hash) {
		HistoricPoseidonRoots::<T>::remove(root);
	}

	/// Get historic roots order
	pub fn get_historic_roots_order<T: Config>() -> BoundedVec<Hash, T::MaxHistoricRoots> {
		HistoricRootsOrder::<T>::get()
	}

	/// Set historic roots order
	pub fn set_historic_roots_order<T: Config>(order: BoundedVec<Hash, T::MaxHistoricRoots>) {
		HistoricRootsOrder::<T>::put(order);
	}

	/// Find leaf index for a commitment (linear scan)
	pub fn find_leaf_index<T: Config>(commitment: &Commitment) -> Option<u32> {
		let size = Self::get_tree_size::<T>();
		for i in 0..size {
			#[allow(clippy::collapsible_if)]
			if let Some(c) = Self::get_leaf::<T>(i) {
				if c == *commitment {
					return Some(i);
				}
			}
		}
		None
	}

	/// Get all leaves up to current size
	pub fn get_all_leaves<T: Config>() -> sp_std::vec::Vec<Hash> {
		let size = Self::get_tree_size::<T>();
		(0..size)
			.filter_map(|i| Self::get_leaf::<T>(i).map(|c| c.0))
			.collect()
	}
}
