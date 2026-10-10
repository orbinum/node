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

	// ── Subtree roots (runtime API v4) ────────────────────────────────────────

	mod subtree_roots {
		use super::*;
		use crate::{
			Pallet,
			merkle::{get_zero_hash_cached, hash_pair},
			types::{SUBTREE_LEVEL, SubtreeRoots},
		};

		const DEPTH: usize = crate::types::DEFAULT_TREE_DEPTH;
		const LEVEL: usize = SUBTREE_LEVEL as usize;

		/// `n` leaves: tree 0 seals at the mock's cap of 8.
		fn insert(n: u8) {
			for i in 0..n {
				assert_ok!(Pallet::<Test>::insert_leaf(Commitment::new([i + 1; 32])));
			}
		}

		/// The node at `level` (>= LEVEL) over the served roots, the zero hash
		/// past the last one, as a wallet folds it.
		fn upper(roots: &[[u8; 32]], level: usize, index: usize) -> [u8; 32] {
			if level == LEVEL {
				return roots
					.get(index)
					.copied()
					.unwrap_or_else(|| get_zero_hash_cached(LEVEL));
			}
			if (index << (level - LEVEL)) >= roots.len() {
				return get_zero_hash_cached(level);
			}
			hash_pair(
				&upper(roots, level - 1, 2 * index),
				&upper(roots, level - 1, 2 * index + 1),
			)
		}

		/// A leaf's path built as a wallet does: the lower levels from the
		/// leaves of its block, the upper ones from the served roots.
		fn wallet_path(
			served: &SubtreeRoots,
			block_leaves: &[[u8; 32]],
			local: usize,
		) -> Vec<[u8; 32]> {
			let mut layer: Vec<[u8; 32]> = (0..1 << LEVEL)
				.map(|i| {
					block_leaves
						.get(i)
						.copied()
						.unwrap_or_else(|| get_zero_hash_cached(0))
				})
				.collect();
			let mut path = Vec::new();
			let offset = local & ((1 << LEVEL) - 1);
			for lvl in 0..LEVEL {
				path.push(layer[(offset >> lvl) ^ 1]);
				layer = layer.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
			}
			assert_eq!(
				layer[0],
				served.roots[local >> LEVEL],
				"the block root is the served one"
			);
			for lvl in LEVEL..DEPTH {
				path.push(upper(&served.roots, lvl, (local >> lvl) ^ 1));
			}
			path
		}

		fn leaves_of(tree_id: u32, n: u32) -> Vec<[u8; 32]> {
			(0..n)
				.map(|i| {
					crate::storage::MerkleRepository::get_leaf::<Test>(tree_id * 8 + i)
						.unwrap()
						.0
				})
				.collect()
		}

		#[test]
		fn the_served_roots_fold_to_the_anchoring_root() {
			new_test_ext().execute_with(|| {
				insert(11);
				for tree_id in [0, 1] {
					let s = Pallet::<Test>::get_subtree_roots(tree_id, 0, 4096).unwrap();
					assert_eq!(upper(&s.roots, DEPTH, 0), s.root, "tree {tree_id}");
				}
				let sealed = Pallet::<Test>::get_subtree_roots(0, 0, 10).unwrap();
				assert!(sealed.sealed);
				assert_eq!(sealed.tree_leaves, 8);
				assert_eq!(
					sealed.root,
					crate::storage::MerkleRepository::get_sealed_root::<Test>(0).unwrap()
				);
				let active = Pallet::<Test>::get_subtree_roots(1, 0, 10).unwrap();
				assert!(!active.sealed);
				assert_eq!(active.tree_leaves, 3);
				assert_eq!(
					active.root,
					crate::storage::MerkleRepository::get_poseidon_root::<Test>()
				);
			});
		}

		/// Every leaf's path built from block leaves and served roots is the
		/// path the node serves, in a sealed and in the active tree.
		#[test]
		fn a_wallet_built_path_is_the_node_path() {
			new_test_ext().execute_with(|| {
				insert(13);
				for (tree_id, n) in [(0u32, 8u32), (1, 5)] {
					let served = Pallet::<Test>::get_subtree_roots(tree_id, 0, 4096).unwrap();
					let leaves = leaves_of(tree_id, n);
					for local in 0..n {
						let node = Pallet::<Test>::get_merkle_proof(tree_id * 8 + local).unwrap();
						assert_eq!(
							wallet_path(&served, &leaves, local as usize),
							node.siblings.to_vec(),
							"tree {tree_id} leaf {local}"
						);
					}
				}
			});
		}

		/// The last block of the active tree changes as leaves land; the root
		/// served with it always matches.
		#[test]
		fn the_partial_block_tracks_the_live_root() {
			new_test_ext().execute_with(|| {
				for i in 0..7u8 {
					assert_ok!(Pallet::<Test>::insert_leaf(Commitment::new([i + 1; 32])));
					let s = Pallet::<Test>::get_subtree_roots(0, 0, 1).unwrap();
					assert_eq!(upper(&s.roots, DEPTH, 0), s.root, "after {} leaves", i + 1);
				}
			});
		}

		/// A sealed tree's node missing from storage (pruned under an earlier,
		/// higher cut) is rebuilt from its leaves.
		#[test]
		fn a_pruned_node_of_a_sealed_tree_is_rebuilt() {
			new_test_ext().execute_with(|| {
				insert(9);
				let before = Pallet::<Test>::get_subtree_roots(0, 0, 1).unwrap();
				crate::pallet::MerkleNodes::<Test>::remove((0u32, SUBTREE_LEVEL, 0u32));
				assert_eq!(Pallet::<Test>::get_subtree_roots(0, 0, 1).unwrap(), before);
			});
		}

		#[test]
		fn windows_and_missing_trees() {
			new_test_ext().execute_with(|| {
				let empty = Pallet::<Test>::get_subtree_roots(0, 0, 10).unwrap();
				assert_eq!(
					(empty.tree_leaves, empty.roots.len(), empty.sealed),
					(0, 0, false)
				);
				assert_eq!(
					Pallet::<Test>::get_subtree_roots(1, 0, 10),
					None,
					"no tree 1 yet"
				);
				insert(9);
				assert_eq!(Pallet::<Test>::get_subtree_roots(2, 0, 10), None);
				assert_eq!(
					Pallet::<Test>::get_subtree_roots(0, 1, 10)
						.unwrap()
						.roots
						.len(),
					0,
					"past the last block"
				);
				assert_eq!(
					Pallet::<Test>::get_subtree_roots(0, 0, 0)
						.unwrap()
						.roots
						.len(),
					0
				);
				assert_eq!(
					Pallet::<Test>::get_subtree_roots(0, u32::MAX, u32::MAX)
						.unwrap()
						.roots
						.len(),
					0
				);
			});
		}
	}
}
