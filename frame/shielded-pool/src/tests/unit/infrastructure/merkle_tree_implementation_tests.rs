//! Merkle tree implementation tests
//!
//! Tests for the incremental Merkle tree data structure implementation.

use crate::infrastructure::merkle_tree::{
	IncrementalMerkleTree, compute_root_from_leaves, hash_pair,
};

#[test]
fn test_empty_tree() {
	let tree: IncrementalMerkleTree<20> = IncrementalMerkleTree::new();
	assert_eq!(tree.size(), 0);
	assert!(!tree.is_full());
}

#[test]
fn test_insert_single_leaf() {
	let mut tree: IncrementalMerkleTree<20> = IncrementalMerkleTree::new();
	let leaf = [1u8; 32];

	let index = tree.insert(leaf).unwrap();
	assert_eq!(index, 0);
	assert_eq!(tree.size(), 1);
}

#[test]
fn test_insert_multiple_leaves() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();

	for i in 0..8 {
		let leaf = [i as u8; 32];
		let index = tree.insert(leaf).unwrap();
		assert_eq!(index, i);
	}

	assert_eq!(tree.size(), 8);
}

#[test]
fn test_tree_full() {
	let mut tree: IncrementalMerkleTree<2> = IncrementalMerkleTree::new();

	// Tree with depth 2 can hold 4 leaves
	for i in 0..4 {
		tree.insert([i as u8; 32]).unwrap();
	}

	assert!(tree.is_full());
	assert!(tree.insert([5u8; 32]).is_err());
}

#[test]
fn test_root_changes_with_inserts() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();

	let root1 = tree.root();
	tree.insert([1u8; 32]).unwrap();
	let root2 = tree.root();
	tree.insert([2u8; 32]).unwrap();
	let root3 = tree.root();

	assert_ne!(root1, root2);
	assert_ne!(root2, root3);
	assert_ne!(root1, root3);
}

#[test]
fn test_proof_verification() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let mut leaves = Vec::new();

	// Insert some leaves
	for i in 0..4 {
		let leaf = [i as u8; 32];
		leaves.push(leaf);
		tree.insert(leaf).unwrap();
	}

	// Generate and verify proof for each leaf
	for (i, leaf) in leaves.iter().enumerate() {
		let proof = tree.generate_proof(i as u32, &leaves).unwrap();
		let verified = IncrementalMerkleTree::<4>::verify_proof(&tree.root(), leaf, &proof);
		assert!(verified, "Proof verification failed for leaf {i}");
	}
}

#[test]
fn test_invalid_proof() {
	let mut tree: IncrementalMerkleTree<4> = IncrementalMerkleTree::new();
	let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();

	for leaf in &leaves {
		tree.insert(*leaf).unwrap();
	}

	let proof = tree.generate_proof(0, &leaves).unwrap();

	// Verify with wrong leaf should fail
	let wrong_leaf = [99u8; 32];
	assert!(!IncrementalMerkleTree::<4>::verify_proof(
		&tree.root(),
		&wrong_leaf,
		&proof
	));
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
