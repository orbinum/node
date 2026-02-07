//! Merkle tree tests
//!
//! Tests for Merkle tree operations and integrity.

use crate::infrastructure::merkle_tree::{
	IncrementalMerkleTree, get_zero_hash_cached, hash_pair, zero_hash_at_level,
};
use crate::tests::helpers::*;
use crate::{Commitment, mock::*};
use frame_support::assert_ok;

// ============================================================================
// Integration Tests (existing)
// ============================================================================

#[test]
fn multiple_shields_update_tree() {
	new_test_ext().execute_with(|| {
		// Shield 3 times
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

		// Pool balance should be 600
		assert_eq!(crate::PoolBalance::<Test>::get(), 600);
	});
}

// ============================================================================
// Unit Tests - Fase 2.2: Tests Poseidon/Blake2
// ============================================================================

/// Test 2.2.1: Hash pair debe ser determinístico
#[test]
fn test_hash_pair_deterministic() {
	let a = [1u8; 32];
	let b = [2u8; 32];

	let hash1 = hash_pair(&a, &b);
	let hash2 = hash_pair(&a, &b);

	assert_eq!(hash1, hash2);
}

/// Test 2.2.2: Orden de inputs debe importar
#[test]
fn test_hash_pair_order_matters() {
	let a = [1u8; 32];
	let b = [2u8; 32];

	let hash_ab = hash_pair(&a, &b);
	let hash_ba = hash_pair(&b, &a);

	assert_ne!(hash_ab, hash_ba);
}

/// Test 2.2.3: Merkle tree insertion
#[test]
fn test_merkle_tree_insertion() {
	let mut tree = IncrementalMerkleTree::<20>::new();

	let leaf = [42u8; 32];
	let index = tree.insert(leaf).expect("insert failed");

	assert_eq!(index, 0);
	assert_eq!(tree.next_index, 1);
	assert_ne!(tree.root, [0u8; 32]);
}

/// Test 2.2.4: Zero hashes consistency
#[test]
fn test_zero_hashes_consistency() {
	let zero0 = zero_hash_at_level(0);
	assert_eq!(zero0, [0u8; 32]);

	let zero1 = zero_hash_at_level(1);
	let expected_zero1 = hash_pair(&zero0, &zero0);
	assert_eq!(zero1, expected_zero1);
}

/// Test 2.2.5: Cached zero hashes
#[test]
fn test_cached_zero_hashes() {
	for level in 0..20 {
		let computed = zero_hash_at_level(level);
		let cached = get_zero_hash_cached(level);
		assert_eq!(computed, cached);
	}
}

/// Test 2.2.6: Multiple inserts
#[test]
fn test_multiple_inserts() {
	let mut tree = IncrementalMerkleTree::<4>::new();

	for i in 0..5u8 {
		let leaf = [i; 32];
		let index = tree.insert(leaf).expect("insert failed");
		assert_eq!(index as u8, i);
	}

	assert_eq!(tree.next_index, 5);
}

/// Test 2.2.7: Full tree rejects insert
#[test]
fn test_full_tree_rejects_insert() {
	let mut tree = IncrementalMerkleTree::<2>::new();

	for i in 0..4u8 {
		let leaf = [i; 32];
		tree.insert(leaf).expect("insert failed");
	}

	let overflow_leaf = [99u8; 32];
	let result = tree.insert(overflow_leaf);

	assert!(result.is_err());
}

/// Test 2.2.8: Root changes with insert
#[test]
fn test_root_changes_with_insert() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	let initial_root = tree.root;

	let leaf1 = [1u8; 32];
	tree.insert(leaf1).expect("insert failed");
	let root1 = tree.root;
	assert_ne!(root1, initial_root);

	let leaf2 = [2u8; 32];
	tree.insert(leaf2).expect("insert failed");
	let root2 = tree.root;
	assert_ne!(root2, root1);
}

/// Test 2.2.9: Merkle proof verification
#[test]
fn test_merkle_proof_verification() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

	for leaf in &leaves {
		tree.insert(*leaf).expect("insert failed");
	}

	let path = tree.generate_proof(1, &leaves).expect("proof failed");
	let is_valid = IncrementalMerkleTree::<4>::verify_proof(&tree.root, &leaves[1], &path);
	assert!(is_valid);
}

/// Test 2.2.10: Invalid proof fails
#[test]
fn test_invalid_merkle_proof_fails() {
	let mut tree = IncrementalMerkleTree::<4>::new();
	let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

	for leaf in &leaves {
		tree.insert(*leaf).expect("insert failed");
	}

	let path = tree.generate_proof(1, &leaves).expect("proof failed");
	let wrong_leaf = [99u8; 32];
	let is_valid = IncrementalMerkleTree::<4>::verify_proof(&tree.root, &wrong_leaf, &path);
	assert!(!is_valid);
}

/// Test 2.2.11: Empty tree root
#[test]
fn test_empty_tree_root() {
	let tree = IncrementalMerkleTree::<4>::new();

	let mut expected = [0u8; 32];
	for _ in 0..4 {
		expected = hash_pair(&expected, &expected);
	}

	assert_eq!(tree.root, expected);
}

/// Test 2.2.12: Tree capacity
#[test]
fn test_tree_capacity() {
	let tree2 = IncrementalMerkleTree::<2>::new();
	assert_eq!(tree2.capacity(), 4);

	let tree4 = IncrementalMerkleTree::<4>::new();
	assert_eq!(tree4.capacity(), 16);

	let tree20 = IncrementalMerkleTree::<20>::new();
	assert_eq!(tree20.capacity(), 1_048_576);
}
