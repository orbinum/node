// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Merkle tree: hashing, the incremental frontier, the on-chain service,
//! the forest and the historic-root window.

use crate::{
	merkle::{
		MAX_ROOTS_PRUNED_PER_INSERT,
		batch::compute_root_from_leaves_poseidon,
		hashing::{get_zero_hash_cached, hash_pair, hash_pair_poseidon, zero_hash_at_level},
		service::MerkleTreeService,
		tree::IncrementalMerkleTree,
	},
	pallet::Event,
	storage::MerkleRepository,
	tests::mock::{System, Test, new_test_ext},
	types::{Commitment, Hash},
};

// ── Hash functions ──────────────────────────────────────────────────────

#[test]
fn hash_pair_poseidon_deterministic() {
	let left = [0x01u8; 32];
	let right = [0x02u8; 32];
	let h1 = hash_pair_poseidon(&left, &right);
	let h2 = hash_pair_poseidon(&left, &right);
	assert_eq!(h1, h2);
	assert_ne!(h1, [0u8; 32]);
}

#[test]
fn hash_pair_poseidon_not_commutative() {
	let left = [0x01u8; 32];
	let right = [0x02u8; 32];
	let h1 = hash_pair_poseidon(&left, &right);
	let h2 = hash_pair_poseidon(&right, &left);
	assert_ne!(h1, h2);
}

#[test]
fn hash_pair_delegates_to_poseidon() {
	let left = [0x03u8; 32];
	let right = [0x04u8; 32];
	assert_eq!(hash_pair(&left, &right), hash_pair_poseidon(&left, &right));
}

#[test]
fn zero_hash_level_0_is_all_zeros() {
	assert_eq!(zero_hash_at_level(0), [0u8; 32]);
}

#[test]
fn zero_hash_level_1_is_hash_of_zeros() {
	let expected = hash_pair(&[0u8; 32], &[0u8; 32]);
	assert_eq!(zero_hash_at_level(1), expected);
}

#[test]
fn zero_hash_levels_are_distinct() {
	let h0 = zero_hash_at_level(0);
	let h1 = zero_hash_at_level(1);
	let h2 = zero_hash_at_level(2);
	assert_ne!(h0, h1);
	assert_ne!(h1, h2);
}

#[test]
fn get_zero_hash_cached_matches_uncached() {
	for level in 0..5usize {
		assert_eq!(get_zero_hash_cached(level), zero_hash_at_level(level));
	}
}

/// The ladder used to be defined recursively. Turning it into a loop must not
/// move a single digest: these hashes stand in for empty subtrees inside
/// every Merkle path the chain has ever served, so a divergence at any level
/// would invalidate proofs against notes already on chain.
///
/// Checked against a local recursive reference rather than against stored
/// values, so the property survives a change to the hash function itself.
#[test]
fn iterative_zero_hash_matches_the_recursive_definition() {
	fn recursive(level: usize) -> Hash {
		if level == 0 {
			return [0u8; 32];
		}
		let prev = recursive(level - 1);
		hash_pair(&prev, &prev)
	}

	// Past 20 as well: that is where `get_zero_hash_cached` stops using its
	// table and falls through to the function being changed here.
	for level in 0..=24usize {
		assert_eq!(
			zero_hash_at_level(level),
			recursive(level),
			"zero hash diverged at level {level}"
		);
	}
}

/// The cache and the function must agree across the boundary of the table,
/// not just inside it — level 21 and up is the fall-through path.
#[test]
fn cached_and_computed_agree_past_the_cache_boundary() {
	for level in 19..=23usize {
		assert_eq!(
			get_zero_hash_cached(level),
			zero_hash_at_level(level),
			"cache and computation disagree at level {level}"
		);
	}
}

/// A level far past anything the tree uses must return rather than exhaust
/// the stack. The recursion this replaces spent one frame per level against
/// the runtime's fixed 1 MB Wasm stack, where an overflow downs the node
/// instead of failing the call.
#[test]
fn a_large_level_returns_instead_of_overflowing_the_stack() {
	// Measured on a 1 MiB thread, matching the runtime's Wasm stack: a bare
	// recursion of this shape returns at 10_000 frames and aborts the process
	// at 20_000 — not a catchable panic, the whole runtime goes. The loop
	// returns at 5_000 with the same stack, and would at any depth: it uses a
	// constant number of frames.
	//
	// Kept at 5_000 rather than higher because each level is a Poseidon hash
	// and the property being shown is "returns at all", not "returns fast".
	let deep = zero_hash_at_level(5_000);
	assert_ne!(deep, [0u8; 32]);
}

// ── IncrementalMerkleTree ───────────────────────────────────────────────

#[test]
fn tree_new_has_zero_size() {
	let tree = IncrementalMerkleTree::<4>::new();
	assert_eq!(tree.size(), 0);
}

#[test]
fn tree_new_root_is_non_zero() {
	let tree = IncrementalMerkleTree::<4>::new();
	assert_ne!(tree.root(), [0u8; 32]);
}

#[test]
fn tree_capacity_is_power_of_two() {
	assert_eq!(IncrementalMerkleTree::<4>::new().capacity(), 16);
	assert_eq!(IncrementalMerkleTree::<2>::new().capacity(), 4);
}

/// `capacity()` shifts into a `u32`, so depth 31 is the last one that holds.
/// Past it the shift is undefined — release builds wrap to 1 and the tree
/// declares itself full after a single leaf — which is why a const assertion
/// on the type rejects those depths at compile time. That case cannot be
/// tested at runtime: it does not build. This pins the boundary that does.
#[test]
fn capacity_holds_at_the_deepest_supported_tree() {
	assert_eq!(IncrementalMerkleTree::<31>::new().capacity(), 1u32 << 31);
	assert_eq!(IncrementalMerkleTree::<20>::new().capacity(), 1_048_576);
}

/// Production depth: the value `integrity_test` pins and every client
/// derives `tree_id` from.
#[test]
fn production_depth_capacity_is_two_to_the_twenty() {
	assert_eq!(
		IncrementalMerkleTree::<{ crate::types::DEFAULT_TREE_DEPTH }>::new().capacity(),
		1_048_576
	);
}

#[test]
fn tree_insert_returns_sequential_indices() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	assert_eq!(tree.insert([0x01u8; 32]).unwrap(), 0);
	assert_eq!(tree.insert([0x02u8; 32]).unwrap(), 1);
	assert_eq!(tree.insert([0x03u8; 32]).unwrap(), 2);
	assert_eq!(tree.size(), 3);
}

#[test]
fn tree_root_changes_after_insert() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	let root_before = tree.root();
	tree.insert([0xAAu8; 32]).unwrap();
	assert_ne!(tree.root(), root_before);
}

#[test]
fn tree_full_rejects_further_inserts() {
	let mut tree = IncrementalMerkleTree::<2>::new();
	for i in 0u8..4 {
		tree.insert([i; 32]).unwrap();
	}
	assert!(tree.is_full());
	assert!(tree.insert([0xFFu8; 32]).is_err());
}

#[test]
fn tree_default_equals_new() {
	let t1 = IncrementalMerkleTree::<4>::new();
	let t2 = IncrementalMerkleTree::<4>::default();
	assert_eq!(t1.root(), t2.root());
	assert_eq!(t1.size(), t2.size());
}

#[test]
fn tree_generate_and_verify_proof_passes() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	let leaves = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
	for &leaf in &leaves {
		tree.insert(leaf).unwrap();
	}
	let proof = tree.generate_proof(0, &leaves).unwrap();
	assert!(IncrementalMerkleTree::<4>::verify_proof(
		&tree.root(),
		&leaves[0],
		&proof
	));
}

#[test]
fn tree_proof_fails_for_wrong_leaf() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	let leaves = [[0x01u8; 32], [0x02u8; 32]];
	for &l in &leaves {
		tree.insert(l).unwrap();
	}
	let proof = tree.generate_proof(0, &leaves).unwrap();
	assert!(!IncrementalMerkleTree::<4>::verify_proof(
		&tree.root(),
		&[0xFFu8; 32],
		&proof
	));
}

#[test]
fn tree_generate_proof_out_of_bounds_fails() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	tree.insert([0x01u8; 32]).unwrap();
	let leaves = [[0x01u8; 32]];
	assert!(tree.generate_proof(5, &leaves).is_err());
}

// ── compute_root_from_leaves_poseidon ───────────────────────────────────

#[test]
fn compute_root_poseidon_empty_is_zero() {
	assert_eq!(compute_root_from_leaves_poseidon::<4>(&[]), [0u8; 32]);
}

#[test]
fn compute_root_poseidon_single_leaf_nonzero() {
	let root = compute_root_from_leaves_poseidon::<4>(&[[0x01u8; 32]]);
	assert_ne!(root, [0u8; 32]);
	assert_ne!(root, [0x01u8; 32]);
}

#[test]
fn compute_root_poseidon_same_leaves_same_root() {
	let leaves = [[0x01u8; 32], [0x02u8; 32]];
	let r1 = compute_root_from_leaves_poseidon::<4>(&leaves);
	let r2 = compute_root_from_leaves_poseidon::<4>(&leaves);
	assert_eq!(r1, r2);
}

#[test]
fn compute_root_poseidon_different_leaves_different_roots() {
	let r1 = compute_root_from_leaves_poseidon::<4>(&[[0x01u8; 32]]);
	let r2 = compute_root_from_leaves_poseidon::<4>(&[[0x02u8; 32]]);
	assert_ne!(r1, r2);
}

// ── MerkleTreeService (FRAME-backed) ────────────────────────────────────

#[test]
fn service_insert_leaf_returns_sequential_indices() {
	new_test_ext().execute_with(|| {
		let c0 = Commitment::new([0x01u8; 32]);
		let c1 = Commitment::new([0x02u8; 32]);
		assert_eq!(MerkleTreeService::insert_leaf::<Test>(c0).unwrap(), 0);
		assert_eq!(MerkleTreeService::insert_leaf::<Test>(c1).unwrap(), 1);
	});
}

#[test]
fn service_insert_duplicate_fails() {
	new_test_ext().execute_with(|| {
		let c = Commitment::new([0x01u8; 32]);
		MerkleTreeService::insert_leaf::<Test>(c).unwrap();
		// Duplicates are detected through `CommitmentMemos`, which the operations
		// layer fills on shield and transfer: simulate that.
		use crate::storage::CommitmentRepository;
		use crate::types::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE};
		CommitmentRepository::store_memo::<Test>(
			c,
			EncryptedMemo::from_bytes(&[0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap(),
		);
		assert!(MerkleTreeService::insert_leaf::<Test>(c).is_err());
	});
}

#[test]
fn service_insert_updates_poseidon_root() {
	new_test_ext().execute_with(|| {
		use crate::storage::MerkleRepository;
		let root_before = MerkleRepository::get_poseidon_root::<Test>();
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xAAu8; 32])).unwrap();
		let root_after = MerkleRepository::get_poseidon_root::<Test>();
		assert_ne!(root_before, root_after);
	});
}

#[test]
fn service_insert_adds_root_to_historic() {
	new_test_ext().execute_with(|| {
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xBBu8; 32])).unwrap();
		use crate::storage::MerkleRepository;
		let root = MerkleRepository::get_poseidon_root::<Test>();
		assert!(MerkleTreeService::is_known_root::<Test>(&root));
	});
}

#[test]
fn service_get_merkle_path_none_for_empty_tree() {
	new_test_ext().execute_with(|| {
		assert!(MerkleTreeService::get_merkle_path::<Test>(0).is_none());
	});
}

#[test]
fn service_get_merkle_path_some_after_insert() {
	new_test_ext().execute_with(|| {
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x01u8; 32])).unwrap();
		assert!(MerkleTreeService::get_merkle_path::<Test>(0).is_some());
	});
}

#[test]
fn service_get_merkle_path_none_out_of_bounds() {
	new_test_ext().execute_with(|| {
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x01u8; 32])).unwrap();
		assert!(MerkleTreeService::get_merkle_path::<Test>(99).is_none());
	});
}

#[test]
fn service_verify_merkle_proof_valid_round_trip() {
	new_test_ext().execute_with(|| {
		let leaf = [0x11u8; 32];
		MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
		use crate::storage::MerkleRepository;
		let root = MerkleRepository::get_poseidon_root::<Test>();
		let path = MerkleTreeService::get_merkle_path::<Test>(0).unwrap();
		assert!(MerkleTreeService::verify_merkle_proof(&root, &leaf, &path));
	});
}

#[test]
fn service_verify_merkle_proof_fails_for_wrong_root() {
	new_test_ext().execute_with(|| {
		let leaf = [0x12u8; 32];
		MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
		let path = MerkleTreeService::get_merkle_path::<Test>(0).unwrap();
		assert!(!MerkleTreeService::verify_merkle_proof(
			&[0xFFu8; 32],
			&leaf,
			&path
		));
	});
}

#[test]
fn service_find_leaf_index_none_for_unknown() {
	new_test_ext().execute_with(|| {
		let c = Commitment::new([0xCCu8; 32]);
		assert!(MerkleTreeService::find_leaf_index::<Test>(&c).is_none());
	});
}

#[test]
fn service_find_leaf_index_correct_after_multiple_inserts() {
	new_test_ext().execute_with(|| {
		let c0 = Commitment::new([0x01u8; 32]);
		let c1 = Commitment::new([0x02u8; 32]);
		MerkleTreeService::insert_leaf::<Test>(c0).unwrap();
		MerkleTreeService::insert_leaf::<Test>(c1).unwrap();
		assert_eq!(MerkleTreeService::find_leaf_index::<Test>(&c0), Some(0));
		assert_eq!(MerkleTreeService::find_leaf_index::<Test>(&c1), Some(1));
	});
}

#[test]
fn insert_leaf_populates_commitment_to_leaf_index() {
	use crate::storage::MerkleRepository;
	new_test_ext().execute_with(|| {
		let c0 = Commitment::new([0xD0u8; 32]);
		let c1 = Commitment::new([0xD1u8; 32]);
		let c2 = Commitment::new([0xD2u8; 32]);
		MerkleTreeService::insert_leaf::<Test>(c0).unwrap();
		MerkleTreeService::insert_leaf::<Test>(c1).unwrap();
		MerkleTreeService::insert_leaf::<Test>(c2).unwrap();
		// Reverse index must be populated for every inserted commitment
		assert_eq!(
			MerkleRepository::get_commitment_leaf_index::<Test>(&c0),
			Some(0)
		);
		assert_eq!(
			MerkleRepository::get_commitment_leaf_index::<Test>(&c1),
			Some(1)
		);
		assert_eq!(
			MerkleRepository::get_commitment_leaf_index::<Test>(&c2),
			Some(2)
		);
		// Unknown commitment returns None
		assert_eq!(
			MerkleRepository::get_commitment_leaf_index::<Test>(&Commitment::new([0xFFu8; 32])),
			None
		);
	});
}

#[test]
fn insert_leaf_increments_total_commitments_counter() {
	use crate::storage::PoolStatsRepository;
	new_test_ext().execute_with(|| {
		assert_eq!(
			PoolStatsRepository::get_total_commitments_inserted::<Test>(),
			0
		);
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xF0u8; 32])).unwrap();
		assert_eq!(
			PoolStatsRepository::get_total_commitments_inserted::<Test>(),
			1
		);
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xF1u8; 32])).unwrap();
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xF2u8; 32])).unwrap();
		assert_eq!(
			PoolStatsRepository::get_total_commitments_inserted::<Test>(),
			3
		);
	});
}

// ── Stored-node path reads vs recomputed reference ──────────────────────

/// Reference sibling-path builder: recomputes every level from the full
/// leaf set. Oracle for the O(depth) stored-node read path.
fn reference_path(leaves: &[[u8; 32]], leaf_index: usize) -> Vec<[u8; 32]> {
	let mut current_level = leaves.to_vec();
	let mut path = Vec::with_capacity(20);
	let mut target = leaf_index;
	for level in 0..20 {
		if !current_level.len().is_multiple_of(2) {
			current_level.push(get_zero_hash_cached(level));
		}
		let sibling_idx = target ^ 1;
		path.push(if sibling_idx < current_level.len() {
			current_level[sibling_idx]
		} else {
			get_zero_hash_cached(level)
		});
		let mut next = Vec::with_capacity(current_level.len().div_ceil(2));
		for chunk in current_level.chunks(2) {
			let right = chunk
				.get(1)
				.copied()
				.unwrap_or_else(|| get_zero_hash_cached(level));
			next.push(hash_pair_poseidon(&chunk[0], &right));
		}
		current_level = next;
		target /= 2;
	}
	path
}

#[test]
fn stored_node_paths_match_recomputed_reference_for_every_leaf() {
	new_test_ext().execute_with(|| {
		// 7 leaves (< MaxLeavesPerTree): odd count exercises zero-hash
		// padding without sealing the tree.
		let leaves: Vec<[u8; 32]> = (0..7u8).map(|i| [i + 1; 32]).collect();
		for leaf in &leaves {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(*leaf)).unwrap();
		}
		let root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
		for (i, leaf) in leaves.iter().enumerate() {
			let path = MerkleTreeService::get_merkle_path::<Test>(i as u32).unwrap();
			let expected = reference_path(&leaves, i);
			assert_eq!(
				path.siblings.to_vec(),
				expected,
				"stored-node path for leaf {i} must equal recomputed path"
			);
			assert!(
				MerkleTreeService::verify_merkle_proof(&root, leaf, &path),
				"leaf {i} proof must verify against the current root"
			);
		}
	});
}

#[test]
fn first_and_last_leaf_paths_verify() {
	new_test_ext().execute_with(|| {
		let leaves: Vec<[u8; 32]> = (0..6u8).map(|i| [0xA0 + i; 32]).collect();
		for leaf in &leaves {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(*leaf)).unwrap();
		}
		let root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
		for i in [0u32, 5] {
			let path = MerkleTreeService::get_merkle_path::<Test>(i).unwrap();
			assert!(MerkleTreeService::verify_merkle_proof(
				&root,
				&leaves[i as usize],
				&path
			));
		}
	});
}

#[test]
fn single_leaf_tree_path_is_all_zero_hashes() {
	new_test_ext().execute_with(|| {
		let leaf = [0x77u8; 32];
		MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
		let path = MerkleTreeService::get_merkle_path::<Test>(0).unwrap();
		for (level, sibling) in path.siblings.iter().enumerate() {
			assert_eq!(*sibling, get_zero_hash_cached(level));
		}
		let root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
		assert!(MerkleTreeService::verify_merkle_proof(&root, &leaf, &path));
	});
}

#[test]
fn stored_top_nodes_derive_poseidon_root() {
	use crate::storage::MerkleRepository;
	new_test_ext().execute_with(|| {
		for i in 0..5u8 {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([i + 1; 32])).unwrap();
		}
		let left = MerkleRepository::get_node::<Test>(0, 19, 0).expect("top-left node stored");
		let right = MerkleRepository::get_node::<Test>(0, 19, 1)
			.unwrap_or_else(|| get_zero_hash_cached(19));
		assert_eq!(
			hash_pair_poseidon(&left, &right),
			MerkleRepository::get_poseidon_root::<Test>(),
			"level-19 nodes must hash to the stored root"
		);
	});
}

// ── Incremental frontier vs batch consistency ───────────────────────────

#[test]
fn incremental_root_matches_batch_root_after_single_insert() {
	new_test_ext().execute_with(|| {
		let leaf = [0x11u8; 32];
		MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();

		let incremental_root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
		let batch_root = compute_root_from_leaves_poseidon::<20>(&[leaf]);
		assert_eq!(
			incremental_root, batch_root,
			"incremental and batch roots must agree after 1 insert"
		);
	});
}

#[test]
fn incremental_root_matches_batch_root_after_multiple_inserts() {
	new_test_ext().execute_with(|| {
		let leaves = [
			[0x01u8; 32],
			[0x02u8; 32],
			[0x03u8; 32],
			[0x04u8; 32],
			[0x05u8; 32],
		];
		for &leaf in &leaves {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
		}

		let incremental_root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
		let batch_root = compute_root_from_leaves_poseidon::<20>(&leaves);
		assert_eq!(
			incremental_root, batch_root,
			"incremental and batch roots must agree after multiple inserts"
		);
	});
}

#[test]
fn incremental_proof_verifies_against_incremental_root() {
	new_test_ext().execute_with(|| {
		let leaves = [[0x0Au8; 32], [0x0Bu8; 32], [0x0Cu8; 32]];
		for &leaf in &leaves {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
		}

		// Proof computed from all leaves (batch), root stored incrementally.
		// Both must be consistent.
		let root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
		for (i, &leaf) in leaves.iter().enumerate() {
			let path = MerkleTreeService::get_merkle_path::<Test>(i as u32).unwrap();
			assert!(
				MerkleTreeService::verify_merkle_proof(&root, &leaf, &path),
				"proof for leaf {i} must verify against incremental root"
			);
		}
	});
}

#[test]
fn merkle_root_updated_event_carries_correct_old_root() {
	use crate::tests::mock::RuntimeEvent;
	new_test_ext().execute_with(|| {
		let c0 = Commitment::new([0xA0u8; 32]);
		let c1 = Commitment::new([0xA1u8; 32]);
		MerkleTreeService::insert_leaf::<Test>(c0).unwrap();
		let root_after_first = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
		MerkleTreeService::insert_leaf::<Test>(c1).unwrap();

		// The second MerkleRootUpdated event must carry the root stored after the first insert.
		let found = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				&r.event,
				RuntimeEvent::ShieldedPool(crate::Event::MerkleRootUpdated {
					old_root, ..
				}) if *old_root == root_after_first
			)
		});
		assert!(
			found,
			"MerkleRootUpdated event must carry the previous root as old_root"
		);
	});
}

// The frontier, persisted between blocks (separate `execute_with` calls),
// survives the SCALE round trip of `[[u8; 32]; 20]`.
#[test]
fn frontier_survives_storage_round_trip_across_separate_calls() {
	use crate::pallet::MerkleTreeFrontier;

	let mut ext = new_test_ext();

	// Block 1: insert first leaf
	let root_b1 = ext.execute_with(|| {
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x01u8; 32])).unwrap();
		MerkleRepository::get_poseidon_root::<Test>()
	});

	// Block 2: insert second leaf — frontier must be correctly recovered from storage
	let root_b2 = ext.execute_with(|| {
		// Frontier was written in block 1; verify it is non-zero (was persisted)
		let frontier = MerkleTreeFrontier::<Test>::get();
		assert_ne!(
			frontier[0], [0u8; 32],
			"frontier slot 0 must be set after first insert"
		);

		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x02u8; 32])).unwrap();
		MerkleRepository::get_poseidon_root::<Test>()
	});

	assert_ne!(root_b1, root_b2, "root must change with each insert");

	// Block 3: the root after 2 incremental inserts must equal the batch root for same leaves
	let expected =
		ext.execute_with(|| compute_root_from_leaves_poseidon::<20>(&[[0x01u8; 32], [0x02u8; 32]]));

	assert_eq!(
		root_b2, expected,
		"frontier root after 2 round-trips must match batch root"
	);
}

// ── Tree-depth consistency ──────────────────────────────────────────────

/// integrity_test passes when MaxTreeDepth equals the fixed tree depth. The
/// mock is aligned to MAX_TREE_DEPTH, so construction must not panic; a
/// divergent config would abort at runtime construction.
#[test]
fn integrity_test_accepts_aligned_tree_depth() {
	use frame_support::traits::Hooks;
	new_test_ext().execute_with(|| {
		<crate::Pallet<Test> as Hooks<frame_system::pallet_prelude::BlockNumberFor<Test>>>::integrity_test();
	});
}

/// The per-tree capacity must divide the fixed depth-20 leaf space so the
/// forest's global u32 index spans whole trees.
#[test]
fn per_tree_capacity_fits_fixed_depth() {
	use crate::types::MAX_TREE_DEPTH;
	assert_eq!(MAX_TREE_DEPTH, 20);
	let cap = <Test as crate::Config>::MaxLeavesPerTree::get();
	assert!(cap.is_power_of_two() && cap <= 1 << MAX_TREE_DEPTH);
}

// ── Multi-tree forest: sealing and rollover ─────────────────────────────

fn fill_leaves(from: u8, count: u8) {
	for i in 0..count {
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([from + i; 32])).unwrap();
	}
}

#[test]
fn filling_insert_seals_tree_and_resets_active_state() {
	use crate::storage::MerkleRepository;
	new_test_ext().execute_with(|| {
		frame_system::Pallet::<Test>::set_block_number(1);
		fill_leaves(1, 7);
		let last = MerkleTreeService::insert_leaf::<Test>(Commitment::new([8u8; 32])).unwrap();
		assert_eq!(last, 7, "filling insert still returns its global index");

		let sealed = MerkleRepository::get_sealed_root::<Test>(0).expect("tree 0 sealed");
		assert!(MerkleRepository::is_known_root::<Test>(&sealed));
		// Active tree reset: empty frontier, empty root, empty root known.
		assert_eq!(MerkleRepository::get_frontier::<Test>(), [[0u8; 32]; 20]);
		let empty_root = get_zero_hash_cached(20);
		assert_eq!(MerkleRepository::get_poseidon_root::<Test>(), empty_root);
		assert!(MerkleRepository::is_known_root::<Test>(&empty_root));

		// Event order: MerkleRootUpdated carries the FINAL root (the new
		// leaf belongs to it), then TreeSealed.
		let events: sp_std::vec::Vec<_> = frame_system::Pallet::<Test>::events()
			.into_iter()
			.map(|r| r.event)
			.collect();
		let root_pos = events
			.iter()
			.position(|e| {
				matches!(e, crate::tests::mock::RuntimeEvent::ShieldedPool(
					Event::MerkleRootUpdated { new_root, tree_size: 8, .. }
				) if *new_root == sealed)
			})
			.expect("MerkleRootUpdated with final root");
		let seal_pos = events
			.iter()
			.position(|e| {
				matches!(e, crate::tests::mock::RuntimeEvent::ShieldedPool(
					Event::TreeSealed { tree_id: 0, final_root, first_leaf_index: 0, leaf_count: 8 }
				) if *final_root == sealed)
			})
			.expect("TreeSealed event");
		assert!(root_pos < seal_pos);
	});
}

/// The single most important forest test: a sealed tree's final root must
/// survive unbounded activity in later trees — eviction would freeze the
/// funds of every unspent note in the sealed tree.
#[test]
fn sealed_root_survives_historic_ring_eviction() {
	use crate::storage::MerkleRepository;
	new_test_ext().execute_with(|| {
		fill_leaves(1, 8); // seal tree 0
		let sealed = MerkleRepository::get_sealed_root::<Test>(0).unwrap();
		let leaf0 = MerkleRepository::get_leaf::<Test>(0).unwrap().0;
		let path0 = MerkleTreeService::get_merkle_path::<Test>(0).unwrap();

		// MaxHistoricRoots = 100: push far past the window (also sealing
		// more trees along the way).
		for i in 0..120u32 {
			let mut leaf = [0u8; 32];
			leaf[..4].copy_from_slice(&i.to_le_bytes());
			leaf[31] = 0xAA;
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
		}

		assert!(
			MerkleTreeService::is_known_root::<Test>(&sealed),
			"sealed root must never expire"
		);
		assert!(
			MerkleTreeService::verify_merkle_proof(&sealed, &leaf0, &path0),
			"tree-0 note must still prove against its sealed root"
		);
	});
}

#[test]
fn straddling_inserts_land_in_consecutive_trees() {
	use crate::storage::MerkleRepository;
	new_test_ext().execute_with(|| {
		fill_leaves(1, 7);
		let a = MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xE1; 32])).unwrap();
		let b = MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xE2; 32])).unwrap();
		assert_eq!(
			(a, b),
			(7, 8),
			"global index keeps counting across the seal"
		);

		// b is local leaf 0 of tree 1: its root evolved from the empty tree.
		let root = MerkleRepository::get_poseidon_root::<Test>();
		let path_b = MerkleTreeService::get_merkle_path::<Test>(8).unwrap();
		assert!(MerkleTreeService::verify_merkle_proof(
			&root,
			&[0xE2; 32],
			&path_b
		));
		assert_eq!(path_b.indices, [0u8; 20], "local index 0 is all left turns");

		// a still proves against tree 0's sealed root.
		let sealed = MerkleRepository::get_sealed_root::<Test>(0).unwrap();
		let path_a = MerkleTreeService::get_merkle_path::<Test>(7).unwrap();
		assert!(MerkleTreeService::verify_merkle_proof(
			&sealed,
			&[0xE1; 32],
			&path_a
		));
	});
}

#[test]
fn duplicate_commitment_rejected_across_trees() {
	new_test_ext().execute_with(|| {
		let dup = Commitment::new([0xD7; 32]);
		MerkleTreeService::insert_leaf::<Test>(dup).unwrap();
		use crate::storage::CommitmentRepository;
		use crate::types::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE};
		CommitmentRepository::store_memo::<Test>(
			dup,
			EncryptedMemo::from_bytes(&[0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap(),
		);
		fill_leaves(1, 7); // seals tree 0; now in tree 1
		assert!(
			MerkleTreeService::insert_leaf::<Test>(dup).is_err(),
			"same commitment in a later tree would alias the nullifier"
		);
	});
}

/// try_state invariants must hold before, across, and after a seal.
/// Runs only with `--features try-runtime` (the hook is feature-gated).
#[cfg(feature = "try-runtime")]
#[test]
fn try_state_holds_across_seal() {
	use frame_support::traits::Hooks;
	new_test_ext().execute_with(|| {
		let try_state = || {
			<crate::Pallet<Test> as Hooks<
				frame_system::pallet_prelude::BlockNumberFor<Test>,
			>>::try_state(0)
		};
		assert!(try_state().is_ok(), "empty forest");
		fill_leaves(1, 7);
		assert!(try_state().is_ok(), "partially filled tree 0");
		fill_leaves(8, 2); // seals tree 0, opens tree 1
		assert!(try_state().is_ok(), "across the seal");
	});
}

/// Mirrors the sealed-tree spend E2E: a note in tree 0 must still verify
/// against the sealed root after enough later inserts to rotate the whole
/// historic ring.
#[test]
fn sealed_tree_leaf_verifies_after_ring_rotation() {
	use crate::storage::MerkleRepository;
	new_test_ext().execute_with(|| {
		let target = Commitment::new([0x9Au8; 32]);
		MerkleTreeService::insert_leaf::<Test>(target).unwrap();
		for i in 0..120u32 {
			let mut leaf = [0u8; 32];
			leaf[..4].copy_from_slice(&i.to_le_bytes());
			leaf[31] = 0x5A;
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
		}
		let sealed = MerkleRepository::get_sealed_root::<Test>(0).expect("tree 0 sealed");
		let path = MerkleTreeService::get_merkle_path::<Test>(0).expect("path for leaf 0");
		assert!(
			MerkleTreeService::verify_merkle_proof(&sealed, &target.0, &path),
			"tree-0 leaf must verify against the sealed root after 120 later inserts"
		);
	});
}

#[test]
fn multiple_rollovers_keep_every_tree_provable() {
	use crate::storage::MerkleRepository;
	new_test_ext().execute_with(|| {
		// Fill trees 0 and 1, half-fill tree 2 (cap = 8).
		for i in 0..20u8 {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([i + 1; 32])).unwrap();
		}
		let roots = [
			MerkleRepository::get_sealed_root::<Test>(0).expect("tree 0 sealed"),
			MerkleRepository::get_sealed_root::<Test>(1).expect("tree 1 sealed"),
			MerkleRepository::get_poseidon_root::<Test>(),
		];
		assert!(MerkleRepository::get_sealed_root::<Test>(2).is_none());

		for i in 0..20u32 {
			let leaf = [(i + 1) as u8; 32];
			let path = MerkleTreeService::get_merkle_path::<Test>(i).unwrap();
			let root = roots[(i / 8) as usize];
			assert!(
				MerkleTreeService::verify_merkle_proof(&root, &leaf, &path),
				"leaf {i} must prove against its tree's root"
			);
		}
	});
}

// ── Historic-root window ────────────────────────────────────────────────

/// integrity_test rejects a zero root window (checked via the mock's non-zero
/// MaxHistoricRoots passing construction).
#[test]
fn integrity_test_accepts_nonzero_root_window() {
	use frame_support::traits::Hooks;
	new_test_ext().execute_with(|| {
		assert!(<Test as crate::Config>::MaxHistoricRoots::get() > 0);
		<crate::Pallet<Test> as Hooks<frame_system::pallet_prelude::BlockNumberFor<Test>>>::integrity_test();
	});
}

fn retention() -> u64 {
	<Test as crate::Config>::RootRetentionBlocks::get()
}

/// Distinct test root. The last byte is set so `root_numbered(0)` can never
/// collide with the all-zero genesis root, which `is_known_root` accepts
/// unconditionally as the active root and would mask a real expiry.
fn root_numbered(i: u32) -> Hash {
	let mut root = [0u8; 32];
	root[..4].copy_from_slice(&i.to_le_bytes());
	root[31] = 0xAA;
	root
}

/// Activity alone must never expire a root. Inserting far more roots
/// than `MaxHistoricRoots` within one retention window leaves the oldest
/// spendable — under the old insert-counted window it was evicted after
/// `MaxHistoricRoots` inserts regardless of how little time had passed.
#[test]
fn historic_root_survives_heavy_activity_within_window() {
	new_test_ext().execute_with(|| {
		let oldest = root_numbered(0);
		MerkleTreeService::add_poseidon_historic_root::<Test>(oldest);

		// Far more inserts than the cap, all in the same block.
		let cap = <Test as crate::Config>::MaxHistoricRoots::get();
		for i in 1..(cap * 2) {
			MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(i));
		}

		assert!(
			MerkleTreeService::is_known_root::<Test>(&oldest),
			"a root must not expire from activity alone, only from elapsed blocks"
		);
	});
}

/// The active root must stay spendable no matter how long the chain idles.
///
/// Expiries are only refreshed by a leaf insert, so on a quiet chain the
/// current root's window elapses while it is still the root every wallet
/// proves against. Without the active-root exemption the pool wedges: every
/// spend reverts with `UnknownMerkleRoot`, and only a funded `shield` could
/// mint a new root to escape.
#[test]
fn active_root_never_expires_on_an_idle_chain() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		let active = MerkleRepository::get_poseidon_root::<Test>();

		// Idle well past a full retention window — no inserts at all.
		System::set_block_number(start + retention() * 4);

		assert!(
			MerkleTreeService::is_known_root::<Test>(&active),
			"the active root must stay provable on an idle chain"
		);
	});
}

/// An active root older than the window, replaced by an insert, stays
/// spendable for a full window from its replacement: a wallet that proved
/// against it is not refused by the next insert.
#[test]
fn a_replaced_root_counts_its_window_from_its_replacement() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x11u8; 32])).unwrap();
		let old = MerkleRepository::get_poseidon_root::<Test>();

		// Active for longer than a window, then replaced.
		let replaced_at = start + retention() * 3;
		System::set_block_number(replaced_at);
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x22u8; 32])).unwrap();
		assert_ne!(MerkleRepository::get_poseidon_root::<Test>(), old);
		assert!(
			MerkleTreeService::is_known_root::<Test>(&old),
			"replaced root refused right after the insert"
		);

		System::set_block_number(replaced_at + retention());
		assert!(MerkleTreeService::is_known_root::<Test>(&old));
		System::set_block_number(replaced_at + retention() + 1);
		assert!(!MerkleTreeService::is_known_root::<Test>(&old));
	});
}

/// Inserts in the same block refresh the outgoing root once: the roots made
/// within the block already carry a full window.
#[test]
fn replacing_a_root_from_the_same_block_queues_nothing_extra() {
	new_test_ext().execute_with(|| {
		System::set_block_number(System::block_number() + 1);
		let before = MerkleRepository::historic_roots_queued::<Test>();
		for i in 1..=5u8 {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([i; 32])).unwrap();
		}
		// The genesis root, refreshed once, plus one slot per new root.
		assert_eq!(
			MerkleRepository::historic_roots_queued::<Test>(),
			before + 1 + 5
		);
	});
}

/// A root stays spendable for the whole retention window and stops being
/// accepted once it has elapsed.
#[test]
fn historic_root_expires_only_after_retention_blocks() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		let root = root_numbered(0xAA);
		MerkleTreeService::add_poseidon_historic_root::<Test>(root);

		// Last block of the window: still spendable.
		System::set_block_number(start + retention());
		assert!(
			MerkleTreeService::is_known_root::<Test>(&root),
			"root must stay spendable through the final block of its window"
		);

		// One block past the window: gone.
		System::set_block_number(start + retention() + 1);
		assert!(
			!MerkleTreeService::is_known_root::<Test>(&root),
			"root must stop being accepted once its window has elapsed"
		);
	});
}

/// End to end: a root must outlive the mempool longevity a transaction was
/// admitted with, even while the chain keeps inserting commitments.
#[test]
fn root_outlives_tx_longevity_under_load() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		let anchor = root_numbered(0xBB);
		MerkleTreeService::add_poseidon_historic_root::<Test>(anchor);

		// Simulate the chain filling blocks for the whole longevity window,
		// two commitments per block, as `private_transfer` does.
		for block in 1..=crate::validate_unsigned::TX_LONGEVITY {
			System::set_block_number(start + block);
			MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(block as u32 * 2));
			MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(
				block as u32 * 2 + 1,
			));
		}

		assert!(
			MerkleTreeService::is_known_root::<Test>(&anchor),
			"a transaction still valid in the pool must find its root on chain"
		);
	});
}

/// Expired entries drain from the queue as inserts happen, so it does not
/// grow without bound.
#[test]
fn expired_roots_are_pruned_from_the_queue() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		// Genesis seeds one entry; add four more.
		let queued_before = MerkleRepository::historic_roots_queued::<Test>();
		for i in 0..4u32 {
			MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(i));
		}
		assert_eq!(
			MerkleRepository::historic_roots_queued::<Test>(),
			queued_before + 4
		);

		// Past the window every prior entry is expired; one insert drains up
		// to MAX_ROOTS_PRUNED_PER_INSERT of them and appends itself.
		System::set_block_number(start + retention() + 1);
		MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(999));

		// Genesis seeds one entry, so the backlog is 5 against a cap of 4:
		// one insert drains the cap and appends itself.
		assert_eq!(
			MerkleRepository::historic_roots_queued::<Test>(),
			queued_before + 4 - MAX_ROOTS_PRUNED_PER_INSERT as u64 + 1,
			"one insert drains exactly the cap and appends itself"
		);
		for i in 0..4u32 {
			assert!(
				!MerkleTreeService::is_known_root::<Test>(&root_numbered(i)),
				"expired roots must no longer be spendable"
			);
		}
		assert!(MerkleTreeService::is_known_root::<Test>(&root_numbered(
			999
		)));
	});
}

/// Draining is capped per insert so one extrinsic never pays for a whole
/// backlog; the leftovers clear on subsequent inserts.
#[test]
fn queue_drain_is_capped_per_insert() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		let backlog = (MAX_ROOTS_PRUNED_PER_INSERT * 3) as u32;
		for i in 0..backlog {
			MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(i));
		}

		System::set_block_number(start + retention() + 1);
		let before = MerkleRepository::historic_roots_queued::<Test>();
		MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(9001));

		// Drained at most the cap, then appended one — so the queue shrank by
		// strictly less than the whole backlog.
		let after = MerkleRepository::historic_roots_queued::<Test>();
		assert_eq!(
			after,
			before - MAX_ROOTS_PRUNED_PER_INSERT as u64 + 1,
			"one insert drains exactly the cap and appends itself"
		);

		// Enough further inserts clear the rest.
		for i in 0..backlog {
			MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(20_000 + i));
		}
		assert!(
			MerkleRepository::historic_roots_queued::<Test>() <= backlog as u64 + 2,
			"the backlog must not accumulate once inserts keep coming"
		);
	});
}

/// An insert that records two roots (retired and new) prunes one budget in total.
#[test]
fn leaf_insert_prunes_at_most_the_budget_across_its_calls() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x01u8; 32])).unwrap();
		for i in 0..(MAX_ROOTS_PRUNED_PER_INSERT * 3) as u32 {
			MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(i));
		}

		// All expired, and the active root is from an earlier block: retire + append.
		System::set_block_number(start + retention() + 1);
		let before = MerkleRepository::historic_roots_queued::<Test>();
		MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x02u8; 32])).unwrap();

		assert_eq!(
			MerkleRepository::historic_roots_queued::<Test>(),
			before - MAX_ROOTS_PRUNED_PER_INSERT as u64 + 2,
			"two roots recorded, one shared prune budget"
		);
	});
}

/// Head and tail only ever move forward, and the queue never reports a
/// negative or oversized length.
#[test]
fn queue_head_and_tail_stay_monotonic() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		let mut last_head = MerkleRepository::get_historic_roots_head::<Test>();
		let mut last_tail = MerkleRepository::get_historic_roots_tail::<Test>();

		for i in 0..40u32 {
			// Advance past the window every so often so draining kicks in.
			if i % 10 == 0 {
				System::set_block_number(start + retention() * (i as u64 / 10 + 1));
			}
			MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(i));

			let head = MerkleRepository::get_historic_roots_head::<Test>();
			let tail = MerkleRepository::get_historic_roots_tail::<Test>();
			assert!(head >= last_head, "head must never move backwards");
			assert!(tail >= last_tail, "tail must never move backwards");
			assert!(head >= tail, "tail must never overtake head");
			last_head = head;
			last_tail = tail;
		}
	});
}

/// A duplicate root value stays known while any live copy remains, and its
/// expiry is extended rather than shortened by the later insert.
#[test]
fn historic_root_duplicate_survives_partial_eviction() {
	new_test_ext().execute_with(|| {
		let start = System::block_number();
		let dup = [0x77u8; 32];

		// First copy at `start`, second one block later — the later insert
		// extends the expiry.
		MerkleTreeService::add_poseidon_historic_root::<Test>(dup);
		System::set_block_number(start + 1);
		MerkleTreeService::add_poseidon_historic_root::<Test>(dup);

		// Past the first copy's expiry but inside the second's.
		System::set_block_number(start + retention() + 1);
		MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(1));
		assert!(
			MerkleTreeService::is_known_root::<Test>(&dup),
			"duplicate root must stay known while a live copy remains"
		);

		// Past the second copy's expiry too.
		System::set_block_number(start + retention() + 2);
		MerkleTreeService::add_poseidon_historic_root::<Test>(root_numbered(2));
		assert!(
			!MerkleTreeService::is_known_root::<Test>(&dup),
			"duplicate root must expire once every copy has elapsed"
		);
	});
}
