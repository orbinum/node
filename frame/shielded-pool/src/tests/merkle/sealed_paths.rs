// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Paths through sealed trees: one pruned under a higher cut, and a sibling
//! subtree past the tree's capacity.

use crate::{
	Config,
	merkle::{MerkleTreeService, get_zero_hash_cached},
	storage::MerkleRepository,
	tests::mock::{Test, new_test_ext},
	types::Commitment,
};

/// A sealed tree pruned under an earlier, higher cut is missing nodes at
/// levels the current cut keeps. Its paths must still verify against the
/// sealed root: the missing siblings are rebuilt from the leaves. This is what
/// makes lowering `SealedTreePrunedBelowLevel` safe on a live chain.
#[test]
fn a_tree_pruned_under_a_higher_cut_still_serves_valid_paths() {
	new_test_ext().execute_with(|| {
		let cap = <Test as Config>::MaxLeavesPerTree::get();
		let leaves: Vec<Commitment> = (0..cap)
			.map(|i| Commitment::new([i as u8 + 1; 32]))
			.collect();
		for leaf in &leaves {
			MerkleTreeService::insert_leaf::<Test>(*leaf).unwrap();
		}
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xEE; 32])).unwrap();
		let sealed = MerkleRepository::get_sealed_root::<Test>(0).expect("tree 0 sealed");

		// Prune as a cut one level above the mock's would have: the mock keeps
		// this level, so only the fallback can supply it.
		let kept = <Test as Config>::SealedTreePrunedBelowLevel::get();
		for index in 0..(cap >> kept) {
			crate::pallet::MerkleNodes::<Test>::remove((0u32, kept, index));
		}

		for (i, leaf) in leaves.iter().enumerate() {
			let path = MerkleTreeService::get_merkle_path::<Test>(i as u32).unwrap();
			assert!(
				MerkleTreeService::verify_merkle_proof(&sealed, &leaf.0, &path),
				"leaf {i}"
			);
		}
	});
}

/// With `MaxLeavesPerTree` below 2^depth, a sealed tree's sibling subtree past
/// its capacity spans global leaf indices of the NEXT tree. It must still read
/// as empty: those leaves are not this tree's.
#[test]
fn a_sibling_subtree_past_the_tree_capacity_is_empty() {
	new_test_ext().execute_with(|| {
		let cap = <Test as Config>::MaxLeavesPerTree::get();
		for i in 0..(2 * cap) {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([i as u8 + 1; 32])).unwrap();
		}
		// Level log2(cap) node 1 of tree 0 would cover global leaves cap..2·cap,
		// all of them tree 1's.
		let level = cap.trailing_zeros() as usize;
		assert_eq!(
			MerkleTreeService::subtree_root::<Test>(0, level, 1, cap),
			get_zero_hash_cached(level)
		);
		// Inside the tree the subtree is the leaves' own fold, not zero.
		assert_ne!(
			MerkleTreeService::subtree_root::<Test>(0, level, 0, cap),
			get_zero_hash_cached(level)
		);
	});
}
