//! Merkle Repository - Encapsulates Merkle tree storage access

use crate::{
	domain::Commitment,
	domain::value_objects::Hash,
	pallet::{
		Config, HistoricPoseidonRoots, HistoricRoots, HistoricRootsOrder, MerkleLeaves, MerkleRoot,
		MerkleTreeSize, PoseidonRoot,
	},
};
use frame_support::pallet_prelude::*;

/// Repository for Merkle tree storage operations
pub struct MerkleRepository;

impl MerkleRepository {
	/// Get current Blake2 Merkle root
	pub fn get_root<T: Config>() -> Hash {
		MerkleRoot::<T>::get()
	}

	/// Set new Blake2 Merkle root
	pub fn set_root<T: Config>(root: Hash) {
		MerkleRoot::<T>::put(root);
	}

	/// Get current Poseidon Merkle root
	pub fn get_poseidon_root<T: Config>() -> Option<Hash> {
		PoseidonRoot::<T>::get()
	}

	/// Set new Poseidon Merkle root
	pub fn set_poseidon_root<T: Config>(root: Hash) {
		PoseidonRoot::<T>::put(root);
	}

	/// Get active root (Poseidon if available, Blake2 fallback)
	#[cfg(feature = "poseidon-wasm")]
	pub fn get_active_root<T: Config>() -> Hash {
		Self::get_poseidon_root::<T>().unwrap_or_else(|| Self::get_root::<T>())
	}

	#[cfg(not(feature = "poseidon-wasm"))]
	pub fn get_active_root<T: Config>() -> Hash {
		Self::get_root::<T>()
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

	/// Check if Blake2 root is known (historic or current)
	pub fn is_known_blake2_root<T: Config>(root: &Hash) -> bool {
		HistoricRoots::<T>::get(root)
	}

	/// Check if Poseidon root is known (historic or current)
	pub fn is_known_poseidon_root<T: Config>(root: &Hash) -> bool {
		HistoricPoseidonRoots::<T>::get(root)
	}

	/// Check if root is known (checks both Blake2 and Poseidon)
	/// This allows gradual migration and backward compatibility
	pub fn is_known_root<T: Config>(root: &Hash) -> bool {
		// Check Blake2 roots (legacy)
		if Self::is_known_blake2_root::<T>(root) {
			return true;
		}

		// Check Poseidon roots (if feature enabled)
		#[cfg(feature = "poseidon-wasm")]
		{
			if Self::is_known_poseidon_root::<T>(root) {
				return true;
			}
		}

		false
	}

	/// Add Blake2 root to historic roots
	pub fn add_historic_blake2_root<T: Config>(root: Hash) {
		HistoricRoots::<T>::insert(root, true);
	}

	/// Add Poseidon root to historic roots
	pub fn add_historic_poseidon_root<T: Config>(root: Hash) {
		HistoricPoseidonRoots::<T>::insert(root, true);
	}

	/// Add root to historic roots (maintains both if poseidon-wasm enabled)
	pub fn add_historic_root<T: Config>(root: Hash) {
		Self::add_historic_blake2_root::<T>(root);
	}

	/// Add dual roots to historic storage
	/// Used when poseidon-wasm is enabled to maintain both roots
	#[cfg(feature = "poseidon-wasm")]
	pub fn add_dual_historic_roots<T: Config>(blake2_root: Hash, poseidon_root: Hash) {
		Self::add_historic_blake2_root::<T>(blake2_root);
		Self::add_historic_poseidon_root::<T>(poseidon_root);
	}

	/// Remove root from historic roots (removes from both storages)
	pub fn remove_historic_root<T: Config>(root: &Hash) {
		HistoricRoots::<T>::remove(root);

		#[cfg(feature = "poseidon-wasm")]
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
