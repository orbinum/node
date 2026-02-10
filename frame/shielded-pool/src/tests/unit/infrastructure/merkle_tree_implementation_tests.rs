//! IncrementalMerkleTree Implementation Tests
//!
//! Tests for the IncrementalMerkleTree data structure that manages
//! the Poseidon-based Merkle tree in the shielded pool.
//!
//! ## What's Tested:
//! - Tree initialization and state
//! - Leaf insertion mechanics
//! - Proof generation and verification
//! - Capacity and full tree handling
//! - Root computation correctness

use crate::{
	Commitment,
	infrastructure::merkle_tree::{
		IncrementalMerkleTree, compute_root_from_leaves, get_zero_hash_cached, hash_pair,
		zero_hash_at_level,
	},
	mock::*,
	tests::helpers::*,
};
use frame_support::assert_ok;

// ============================================================================
// SECTION 1: Tree Initialization and State
// ============================================================================

#[test]
fn empty_tree_has_correct_initial_state() {
	let tree: IncrementalMerkleTree<20> = IncrementalMerkleTree::new();

	assert_eq!(tree.size(), 0, "Empty tree should have size 0");
	assert!(!tree.is_full(), "Empty tree should not be full");
	assert_eq!(tree.next_index, 0, "Next index should be 0");

	// Empty tree root should be precomputed
	assert_ne!(tree.root, [0u8; 32], "Empty tree should have non-zero root");
}

#[test]
fn tree_capacity_matches_depth() {
	let tree2 = IncrementalMerkleTree::<2>::new();
	assert_eq!(tree2.capacity(), 4, "Depth 2 = 2^2 = 4 leaves");

	let tree4 = IncrementalMerkleTree::<4>::new();
	assert_eq!(tree4.capacity(), 16, "Depth 4 = 2^4 = 16 leaves");

	let tree20 = IncrementalMerkleTree::<20>::new();
	assert_eq!(
		tree20.capacity(),
		1_048_576,
		"Depth 20 = 2^20 = 1,048,576 leaves"
	);
}

#[test]
fn empty_tree_root_computed_correctly() {
	let tree = IncrementalMerkleTree::<4>::new();

	// Manually compute empty root for depth 4
	let mut expected = [0u8; 32];
	for _ in 0..4 {
		expected = hash_pair(&expected, &expected);
	}

	assert_eq!(
		tree.root, expected,
		"Empty tree root should match manual computation"
	);
}

// ============================================================================
// SECTION 2: Leaf Insertion
// ============================================================================

#[test]
fn insert_single_leaf() {
	let mut tree: IncrementalMerkleTree<20> = IncrementalMerkleTree::new();
	let leaf = [1u8; 32];

	let index = tree.insert(leaf).unwrap();

	assert_eq!(index, 0, "First leaf should have index 0");
	assert_eq!(tree.size(), 1, "Tree size should be 1");
	assert_eq!(tree.next_index, 1, "Next index should be 1");
	assert_ne!(tree.root, [0u8; 32], "Root should change after insertion");
}

#[test]
fn insert_multiple_leaves_sequential_indices() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();

	for i in 0..8 {
		let leaf = [i as u8; 32];
		let index = tree.insert(leaf).unwrap();
		assert_eq!(index, i, "Leaf should have sequential index");
	}

	assert_eq!(tree.size(), 8, "Tree should have 8 leaves");
	assert_eq!(tree.next_index, 8, "Next index should be 8");
}

#[test]
fn root_changes_with_each_insert() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	let initial_root = tree.root;

	let leaf1 = [1u8; 32];
	tree.insert(leaf1).unwrap();
	let root1 = tree.root;
	assert_ne!(root1, initial_root, "Root should change after first insert");

	let leaf2 = [2u8; 32];
	tree.insert(leaf2).unwrap();
	let root2 = tree.root;
	assert_ne!(root2, root1, "Root should change after second insert");
	assert_ne!(root2, initial_root, "Root should differ from initial");
}

#[test]
fn full_tree_rejects_insert() {
	let mut tree = IncrementalMerkleTree::<2>::new();

	// Tree with depth 2 can hold 4 leaves
	for i in 0..4u8 {
		tree.insert([i; 32]).unwrap();
	}

	assert!(tree.is_full(), "Tree should be full after 4 inserts");

	let overflow_leaf = [99u8; 32];
	let result = tree.insert(overflow_leaf);

	assert!(result.is_err(), "Inserting into full tree should fail");
}

// ============================================================================
// SECTION 3: Proof Generation and Verification
// ============================================================================

#[test]
fn generate_and_verify_proof_for_all_leaves() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaves: Vec<[u8; 32]> = (1..=4).map(|i| [i as u8; 32]).collect();

	// Insert all leaves
	for leaf in &leaves {
		tree.insert(*leaf).unwrap();
	}

	// Generate and verify proof for each leaf
	for (i, leaf) in leaves.iter().enumerate() {
		let proof = tree.generate_proof(i as u32, &leaves).unwrap();
		let verified = IncrementalMerkleTree::<4>::verify_proof(&tree.root(), leaf, &proof);
		assert!(verified, "Proof verification failed for leaf at index {i}");
	}
}

#[test]
fn single_leaf_proof_verification() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaf = [42u8; 32];

	tree.insert(leaf).unwrap();

	let proof = tree.generate_proof(0, &[leaf]).unwrap();
	assert!(
		IncrementalMerkleTree::<4>::verify_proof(&tree.root(), &leaf, &proof),
		"Single leaf proof should verify"
	);
}

#[test]
fn invalid_proof_fails_verification() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();

	for leaf in &leaves {
		tree.insert(*leaf).unwrap();
	}

	let proof = tree.generate_proof(0, &leaves).unwrap();

	// Verify with wrong leaf should fail
	let wrong_leaf = [99u8; 32];
	assert!(
		!IncrementalMerkleTree::<4>::verify_proof(&tree.root(), &wrong_leaf, &proof),
		"Proof with wrong leaf should fail verification"
	);
}

#[test]
fn proof_for_different_leaves_differs() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaves: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

	for leaf in &leaves {
		tree.insert(*leaf).unwrap();
	}

	let proof0 = tree.generate_proof(0, &leaves).unwrap();
	let proof1 = tree.generate_proof(1, &leaves).unwrap();

	// Proofs for different leaves should differ
	assert_ne!(proof0.siblings, proof1.siblings, "Siblings should differ");
}

// ============================================================================
// SECTION 4: Root Computation Validation
// ============================================================================

#[test]
fn compute_root_from_leaves_matches_tree_root() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();

	for leaf in &leaves {
		tree.insert(*leaf).unwrap();
	}

	let computed_root = compute_root_from_leaves::<4>(&leaves);
	assert_eq!(
		tree.root(),
		computed_root,
		"Computed root should match tree's root"
	);
}

#[test]
fn tree_with_partial_leaves_matches_computation() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaves: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]]; // 3 leaves only

	for leaf in &leaves {
		tree.insert(*leaf).unwrap();
	}

	let computed_root = compute_root_from_leaves::<4>(&leaves);
	assert_eq!(
		tree.root(),
		computed_root,
		"Partial tree root should match computation"
	);
}

// ============================================================================
// SECTION 5: Hash Functions
// ============================================================================

#[test]
fn hash_pair_is_deterministic() {
	let a = [1u8; 32];
	let b = [2u8; 32];

	let hash1 = hash_pair(&a, &b);
	let hash2 = hash_pair(&a, &b);

	assert_eq!(hash1, hash2, "Hash should be deterministic");
}

#[test]
fn hash_pair_order_matters() {
	let a = [1u8; 32];
	let b = [2u8; 32];

	let hash_ab = hash_pair(&a, &b);
	let hash_ba = hash_pair(&b, &a);

	assert_ne!(hash_ab, hash_ba, "Hash order should matter");
}

#[test]
fn zero_hashes_are_consistent() {
	// Computed and cached zero hashes should match
	for level in 0..20 {
		let computed = zero_hash_at_level(level);
		let cached = get_zero_hash_cached(level);
		assert_eq!(
			computed, cached,
			"Computed and cached zero hash should match at level {level}"
		);
	}
}

#[test]
fn zero_hash_level_0_is_all_zeros() {
	let zero0 = zero_hash_at_level(0);
	assert_eq!(zero0, [0u8; 32], "Zero hash at level 0 should be all zeros");
}

#[test]
fn zero_hash_structure_validated() {
	let zero0 = zero_hash_at_level(0);
	assert_eq!(zero0, [0u8; 32]);

	// Each level is hash(prev, prev)
	let zero1 = zero_hash_at_level(1);
	let expected_zero1 = hash_pair(&zero0, &zero0);
	assert_eq!(
		zero1, expected_zero1,
		"Zero hash level 1 should be hash(zero0, zero0)"
	);

	let zero2 = zero_hash_at_level(2);
	let expected_zero2 = hash_pair(&zero1, &zero1);
	assert_eq!(
		zero2, expected_zero2,
		"Zero hash level 2 should be hash(zero1, zero1)"
	);
}

// ============================================================================
// SECTION 6: Integration with Pallet
// ============================================================================

#[test]
fn multiple_shields_update_merkle_tree() {
	new_test_ext().execute_with(|| {
		// Shield 3 times with different commitments
		for i in 0..3u8 {
			let commitment = Commitment([i + 1; 32]);
			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0, // native asset
				200u128,
				commitment,
				sample_encrypted_memo_with_seed(i),
			));
		}

		// Tree should have 3 leaves
		assert_eq!(crate::MerkleTreeSize::<Test>::get(), 3);

		// Pool balance should reflect all shields
		assert_eq!(crate::PoolBalance::<Test>::get(), 600);
	});
}

#[test]
fn test_hash_pair_deterministic() {
	let a = [1u8; 32];
	let b = [2u8; 32];

	let hash1 = hash_pair(&a, &b);
	let hash2 = hash_pair(&a, &b);

	assert_eq!(hash1, hash2);
}

#[test]
fn test_hash_pair_order_matters() {
	let a = [1u8; 32];
	let b = [2u8; 32];

	let hash_ab = hash_pair(&a, &b);
	let hash_ba = hash_pair(&b, &a);

	assert_ne!(hash_ab, hash_ba);
}

#[test]
fn test_single_leaf_proof() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaf = [42u8; 32];

	tree.insert(leaf).unwrap();

	let proof = tree.generate_proof(0, &[leaf]).unwrap();
	assert!(IncrementalMerkleTree::<4>::verify_proof(
		&tree.root(),
		&leaf,
		&proof
	));
}

#[test]
fn test_compute_root_from_leaves() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();

	for leaf in &leaves {
		tree.insert(*leaf).unwrap();
	}

	let computed_root = compute_root_from_leaves::<4>(&leaves);
	assert_eq!(tree.root(), computed_root);
}
