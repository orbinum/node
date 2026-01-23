//! Integration tests for Merkle tree operations

use ark_bn254::Fr as Bn254Fr;
use fp_zk_primitives::core::constants::{DEFAULT_TREE_DEPTH, MAX_TREE_DEPTH};
use fp_zk_primitives::core::types::Commitment;
use fp_zk_primitives::crypto::hash::poseidon_hash_2;
use fp_zk_primitives::crypto::merkle::{
	compute_empty_root, compute_merkle_root, verify_merkle_proof,
};

#[test]
fn test_compute_merkle_root_single_level() {
	let leaf = Commitment(Bn254Fr::from(1u64));
	let sibling = Bn254Fr::from(2u64);

	// Test left position
	let root_left = compute_merkle_root(&leaf, &[sibling], &[false]);
	let expected_left = poseidon_hash_2(&[leaf.0, sibling]);
	assert_eq!(root_left, expected_left);

	// Test right position
	let root_right = compute_merkle_root(&leaf, &[sibling], &[true]);
	let expected_right = poseidon_hash_2(&[sibling, leaf.0]);
	assert_eq!(root_right, expected_right);

	// Left and right should be different
	assert_ne!(root_left, root_right);
}

#[test]
fn test_verify_merkle_proof_valid() {
	let leaf = Commitment(Bn254Fr::from(42u64));
	let sibling = Bn254Fr::from(100u64);
	let root = compute_merkle_root(&leaf, &[sibling], &[false]);

	// Valid proof should verify
	assert!(verify_merkle_proof(&leaf, &[sibling], &[false], &root));
}

#[test]
fn test_verify_merkle_proof_invalid_path() {
	let leaf = Commitment(Bn254Fr::from(42u64));
	let sibling = Bn254Fr::from(100u64);
	let root = compute_merkle_root(&leaf, &[sibling], &[false]);

	// Invalid path should fail
	assert!(!verify_merkle_proof(&leaf, &[sibling], &[true], &root));
}

#[test]
fn test_verify_merkle_proof_invalid_leaf() {
	let leaf = Commitment(Bn254Fr::from(42u64));
	let sibling = Bn254Fr::from(100u64);
	let root = compute_merkle_root(&leaf, &[sibling], &[false]);

	// Invalid leaf should fail
	assert!(!verify_merkle_proof(
		&Commitment(Bn254Fr::from(999u64)),
		&[sibling],
		&[false],
		&root
	));
}

#[test]
fn test_verify_merkle_proof_invalid_root() {
	let leaf = Commitment(Bn254Fr::from(42u64));
	let sibling = Bn254Fr::from(100u64);
	let _root = compute_merkle_root(&leaf, &[sibling], &[false]);
	let wrong_root = Bn254Fr::from(999u64);

	// Wrong root should fail
	assert!(!verify_merkle_proof(
		&leaf,
		&[sibling],
		&[false],
		&wrong_root
	));
}

#[test]
fn test_compute_empty_root() {
	let depth_1 = compute_empty_root(1);
	let depth_2 = compute_empty_root(2);
	let depth_3 = compute_empty_root(3);

	// Different depths should produce different roots
	assert_ne!(depth_1, depth_2);
	assert_ne!(depth_2, depth_3);

	// Verify depth 1 manually
	let zero = Bn254Fr::from(0u64);
	let expected = poseidon_hash_2(&[zero, zero]);
	assert_eq!(depth_1, expected);
}

#[test]
fn test_compute_empty_root_depth_2() {
	let depth_2 = compute_empty_root(2);

	// Manually compute depth 2
	let zero = Bn254Fr::from(0u64);
	let level1 = poseidon_hash_2(&[zero, zero]);
	let level2 = poseidon_hash_2(&[level1, level1]);

	assert_eq!(depth_2, level2);
}

#[test]
fn test_multi_level_tree() {
	// Build a 3-level tree manually
	let leaf = Commitment(Bn254Fr::from(123u64));
	let sibling1 = Bn254Fr::from(456u64);
	let sibling2 = Bn254Fr::from(789u64);
	let sibling3 = Bn254Fr::from(101u64);

	let path_elements = vec![sibling1, sibling2, sibling3];
	let path_indices = vec![false, true, false];

	let root = compute_merkle_root(&leaf, &path_elements, &path_indices);

	// Verify the computed root
	assert!(verify_merkle_proof(
		&leaf,
		&path_elements,
		&path_indices,
		&root
	));

	// Invalid proof should fail
	let wrong_indices = vec![true, true, false];
	assert!(!verify_merkle_proof(
		&leaf,
		&path_elements,
		&wrong_indices,
		&root
	));
}

#[test]
fn test_multi_level_tree_manual_verification() {
	let leaf = Commitment(Bn254Fr::from(100u64));
	let sibling1 = Bn254Fr::from(200u64);
	let sibling2 = Bn254Fr::from(300u64);

	let path_elements = vec![sibling1, sibling2];
	let path_indices = vec![false, true];

	// Manually compute root
	let level1 = poseidon_hash_2(&[leaf.0, sibling1]);
	let level2 = poseidon_hash_2(&[sibling2, level1]);

	let computed_root = compute_merkle_root(&leaf, &path_elements, &path_indices);
	assert_eq!(computed_root, level2);
}

#[test]
fn test_default_tree_depth() {
	// Verify DEFAULT_TREE_DEPTH is reasonable
	assert_eq!(DEFAULT_TREE_DEPTH, 20);

	// Should be able to compute empty root for default depth
	let root = compute_empty_root(DEFAULT_TREE_DEPTH);
	assert_ne!(root, Bn254Fr::from(0u64));
}

#[test]
fn test_max_tree_depth() {
	// Verify MAX_TREE_DEPTH is set correctly
	assert_eq!(MAX_TREE_DEPTH, 32);

	// Should be able to compute empty root for max depth
	let root = compute_empty_root(MAX_TREE_DEPTH);
	assert_ne!(root, Bn254Fr::from(0u64));
}

#[test]
#[should_panic(expected = "Path length exceeds maximum tree depth")]
fn test_path_too_long() {
	let leaf = Commitment(Bn254Fr::from(1u64));
	let path_elements = vec![Bn254Fr::from(0u64); MAX_TREE_DEPTH + 1];
	let path_indices = vec![false; MAX_TREE_DEPTH + 1];

	compute_merkle_root(&leaf, &path_elements, &path_indices);
}

#[test]
#[should_panic(expected = "Tree depth exceeds maximum allowed depth")]
fn test_empty_root_too_deep() {
	compute_empty_root(MAX_TREE_DEPTH + 1);
}

#[test]
#[should_panic(expected = "Path elements and indices must have same length")]
fn test_mismatched_path_lengths() {
	let leaf = Commitment(Bn254Fr::from(1u64));
	let path_elements = vec![Bn254Fr::from(2u64), Bn254Fr::from(3u64)];
	let path_indices = vec![false]; // Only 1 index

	compute_merkle_root(&leaf, &path_elements, &path_indices);
}

#[test]
fn test_merkle_tree_with_real_commitments() {
	// Create real commitments as leaves
	use fp_zk_primitives::crypto::commitment::create_commitment;

	let commitment1 = create_commitment(
		Bn254Fr::from(100u64),
		Bn254Fr::from(0u64),
		Bn254Fr::from(12345u64),
		Bn254Fr::from(11111u64),
	);

	let commitment2 = create_commitment(
		Bn254Fr::from(200u64),
		Bn254Fr::from(0u64),
		Bn254Fr::from(67890u64),
		Bn254Fr::from(22222u64),
	);

	// Build tree with commitment1 as leaf, commitment2 as sibling
	let path_elements = vec![commitment2.0];
	let path_indices = vec![false];

	let root = compute_merkle_root(&commitment1, &path_elements, &path_indices);

	// Verify proof
	assert!(verify_merkle_proof(
		&commitment1,
		&path_elements,
		&path_indices,
		&root
	));

	// Verify commitment2 as leaf with commitment1 as sibling
	let path_elements2 = vec![commitment1.0];
	let path_indices2 = vec![true];
	let root2 = compute_merkle_root(&commitment2, &path_elements2, &path_indices2);

	// Roots should be the same (order matters in path indices)
	assert_eq!(root, root2);
}

#[test]
fn test_empty_tree_zero_depth() {
	let root = compute_empty_root(0);
	assert_eq!(
		root,
		Bn254Fr::from(0u64),
		"Empty tree with depth 0 should be zero"
	);
}
