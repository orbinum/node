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

#[cfg(test)]
mod tests {
	use crate::{
		mock::{Test, new_test_ext},
		types::Commitment,
	};
	use frame_support::assert_ok;

	#[test]
	fn get_merkle_tree_info_initial_state_has_zero_size() {
		new_test_ext().execute_with(|| {
			let (_root, size, depth) = crate::Pallet::<Test>::get_merkle_tree_info();
			assert_eq!(size, 0);
			assert_eq!(depth, 20); // MaxTreeDepth = 20 (matches MAX_TREE_DEPTH)
		});
	}

	#[test]
	fn get_merkle_tree_info_size_increments_after_insert() {
		new_test_ext().execute_with(|| {
			assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(
				[0x01u8; 32]
			)));
			let (_root, size, _depth) = crate::Pallet::<Test>::get_merkle_tree_info();
			assert_eq!(size, 1);
		});
	}

	#[test]
	fn get_merkle_tree_info_root_changes_after_insert() {
		new_test_ext().execute_with(|| {
			let (root_before, _, _) = crate::Pallet::<Test>::get_merkle_tree_info();
			assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(
				[0x02u8; 32]
			)));
			let (root_after, _, _) = crate::Pallet::<Test>::get_merkle_tree_info();
			assert_ne!(root_before, root_after);
		});
	}

	#[test]
	fn get_merkle_proof_none_for_empty_tree() {
		new_test_ext().execute_with(|| {
			assert!(crate::Pallet::<Test>::get_merkle_proof(0).is_none());
		});
	}

	#[test]
	fn get_merkle_proof_some_for_existing_leaf() {
		new_test_ext().execute_with(|| {
			assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(
				[0x02u8; 32]
			)));
			assert!(crate::Pallet::<Test>::get_merkle_proof(0).is_some());
		});
	}

	#[test]
	fn get_merkle_proof_none_for_out_of_bounds_index() {
		new_test_ext().execute_with(|| {
			assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(
				[0x03u8; 32]
			)));
			assert!(crate::Pallet::<Test>::get_merkle_proof(99).is_none());
		});
	}

	#[test]
	fn get_root_for_leaf_distinguishes_sealed_and_active_trees() {
		new_test_ext().execute_with(|| {
			// Fill tree 0 (mock cap = 8) and put one leaf in tree 1.
			for i in 0..9u8 {
				assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(
					[i + 1; 32]
				)));
			}
			let sealed = crate::storage::MerkleRepository::get_sealed_root::<Test>(0).unwrap();
			let active = crate::storage::MerkleRepository::get_poseidon_root::<Test>();

			assert_eq!(
				crate::Pallet::<Test>::get_root_for_leaf(0),
				Some((sealed, 0))
			);
			assert_eq!(
				crate::Pallet::<Test>::get_root_for_leaf(7),
				Some((sealed, 0))
			);
			assert_eq!(
				crate::Pallet::<Test>::get_root_for_leaf(8),
				Some((active, 1))
			);
			assert_eq!(crate::Pallet::<Test>::get_root_for_leaf(9), None);
		});
	}

	#[test]
	fn get_forest_info_counts_sealed_trees() {
		new_test_ext().execute_with(|| {
			for i in 0..9u8 {
				assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(
					[i + 1; 32]
				)));
			}
			let (root, size, depth, current_tree_id, sealed_count) =
				crate::Pallet::<Test>::get_forest_info();
			assert_eq!(
				root,
				crate::storage::MerkleRepository::get_poseidon_root::<Test>()
			);
			assert_eq!((size, depth, current_tree_id, sealed_count), (9, 20, 1, 1));
		});
	}

	#[test]
	fn get_merkle_proof_for_commitment_none_when_not_found() {
		new_test_ext().execute_with(|| {
			assert!(crate::Pallet::<Test>::get_merkle_proof_for_commitment([0xFFu8; 32]).is_none());
		});
	}

	#[test]
	fn get_merkle_proof_for_commitment_some_with_correct_index() {
		new_test_ext().execute_with(|| {
			let leaf = [0x10u8; 32];
			assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(leaf)));
			let result = crate::Pallet::<Test>::get_merkle_proof_for_commitment(leaf);
			assert!(result.is_some());
			let (index, _path) = result.unwrap();
			assert_eq!(index, 0);
		});
	}

	#[test]
	fn get_merkle_proof_for_commitment_returns_correct_index_for_third_leaf() {
		new_test_ext().execute_with(|| {
			let c0 = Commitment::new([0x11u8; 32]);
			let c1 = Commitment::new([0x22u8; 32]);
			let c2 = Commitment::new([0x33u8; 32]);
			assert_ok!(crate::Pallet::<Test>::insert_leaf(c0));
			assert_ok!(crate::Pallet::<Test>::insert_leaf(c1));
			assert_ok!(crate::Pallet::<Test>::insert_leaf(c2));
			let (idx, _) = crate::Pallet::<Test>::get_merkle_proof_for_commitment(c2.0).unwrap();
			assert_eq!(idx, 2);
		});
	}
}
