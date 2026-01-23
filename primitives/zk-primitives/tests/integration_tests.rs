//! Integration tests combining all primitives

use ark_bn254::Fr as Bn254Fr;
use fp_zk_primitives::core::constants::{DEFAULT_TREE_DEPTH, NATIVE_ASSET_ID};
use fp_zk_primitives::core::types::{Commitment, Nullifier, SpendingKey};
use fp_zk_primitives::crypto::commitment::{compute_nullifier, create_commitment};
use fp_zk_primitives::crypto::hash::poseidon_hash_2;
use fp_zk_primitives::crypto::merkle::{
	compute_empty_root, compute_merkle_root, verify_merkle_proof,
};
use fp_zk_primitives::models::note::Note;

#[test]
fn test_full_workflow() {
	// Complete workflow: create note → commitment → Merkle proof → nullifier
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);
	let spending_key = SpendingKey(Bn254Fr::from(11111u64));

	// 1. Create a note
	let note = Note::new(100, NATIVE_ASSET_ID, owner, blinding);
	assert_eq!(note.value_u64(), Some(100));

	// 2. Compute commitment
	let commitment = note.commitment();
	assert_ne!(commitment.0, Bn254Fr::from(0u64));

	// 3. Create a simple Merkle tree (depth 1)
	let sibling = Bn254Fr::from(999u64);
	let root = compute_merkle_root(&commitment, &[sibling], &[false]);

	// 4. Verify Merkle proof
	assert!(verify_merkle_proof(
		&commitment,
		&[sibling],
		&[false],
		&root
	));

	// 5. Compute nullifier when spending
	let nullifier = note.nullifier(&spending_key);
	assert_ne!(nullifier.0, Bn254Fr::from(0u64));
	assert_ne!(nullifier.0, commitment.0);
}

#[test]
fn test_multiple_notes_in_tree() {
	let owner1 = Bn254Fr::from(11111u64);
	let owner2 = Bn254Fr::from(22222u64);
	let blinding1 = Bn254Fr::from(33333u64);
	let blinding2 = Bn254Fr::from(44444u64);

	// Create two notes
	let note1 = Note::new(100, NATIVE_ASSET_ID, owner1, blinding1);
	let note2 = Note::new(200, NATIVE_ASSET_ID, owner2, blinding2);

	let commitment1 = note1.commitment();
	let commitment2 = note2.commitment();

	// Build tree with both commitments
	let path_elements = vec![commitment2.0];
	let path_indices = vec![false];
	let root = compute_merkle_root(&commitment1, &path_elements, &path_indices);

	// Verify proof for note1
	assert!(verify_merkle_proof(
		&commitment1,
		&path_elements,
		&path_indices,
		&root
	));

	// Verify proof for note2 (as sibling on right)
	let path_elements2 = vec![commitment1.0];
	let path_indices2 = vec![true];
	assert!(verify_merkle_proof(
		&commitment2,
		&path_elements2,
		&path_indices2,
		&root
	));
}

#[test]
fn test_shield_unshield_workflow() {
	// Simulate shield → wait → unshield workflow
	let owner = Bn254Fr::from(55555u64);
	let blinding = Bn254Fr::from(77777u64);
	let spending_key = SpendingKey(Bn254Fr::from(88888u64));
	let amount = 1000u64;

	// SHIELD: Create note and get commitment
	let note = Note::new(amount, NATIVE_ASSET_ID, owner, blinding);
	let commitment = note.commitment();

	// Insert into Merkle tree (simulated with empty tree)
	let empty_root = compute_empty_root(DEFAULT_TREE_DEPTH);
	let siblings = vec![empty_root; DEFAULT_TREE_DEPTH];
	let indices = vec![false; DEFAULT_TREE_DEPTH];
	let root = compute_merkle_root(&commitment, &siblings, &indices);

	// Verify Merkle proof
	assert!(verify_merkle_proof(&commitment, &siblings, &indices, &root));

	// UNSHIELD: Compute nullifier to spend the note
	let nullifier = note.nullifier(&spending_key);
	assert_ne!(nullifier.0, commitment.0);

	// Verify amount can be recovered
	assert_eq!(note.value_u64(), Some(amount));
}

#[test]
fn test_private_transfer_workflow() {
	// Simulate private transfer: spend note1 → create note2
	let owner1 = Bn254Fr::from(11111u64);
	let owner2 = Bn254Fr::from(22222u64);
	let blinding1 = Bn254Fr::from(33333u64);
	let blinding2 = Bn254Fr::from(44444u64);
	let spending_key1 = SpendingKey(Bn254Fr::from(55555u64));

	// Input: note1 (100 tokens)
	let note1 = Note::new(100, NATIVE_ASSET_ID, owner1, blinding1);
	let commitment1 = note1.commitment();
	let nullifier1 = note1.nullifier(&spending_key1);

	// Output: note2 (100 tokens to new owner)
	let note2 = Note::new(100, NATIVE_ASSET_ID, owner2, blinding2);
	let commitment2 = note2.commitment();

	// Verify commitments are different
	assert_ne!(commitment1.0, commitment2.0);

	// Verify nullifier is computed correctly
	assert_ne!(nullifier1.0, commitment1.0);
	assert_ne!(nullifier1.0, commitment2.0);
}

#[test]
fn test_commitment_functions_compatibility() {
	// Test that different ways of creating commitments produce same result
	let value = Bn254Fr::from(100u64);
	let asset_id = Bn254Fr::from(0u64);
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	// Using crypto function directly
	let commitment1 = create_commitment(value, asset_id, owner, blinding);

	// Using Note
	let note = Note::from_fields(value, asset_id, owner, blinding);
	let commitment2 = note.commitment();

	// Should be the same
	assert_eq!(commitment1.0, commitment2.0);
}

#[test]
fn test_nullifier_functions_compatibility() {
	let commitment = Commitment(Bn254Fr::from(99999u64));
	let spending_key = SpendingKey(Bn254Fr::from(55555u64));

	// Using crypto function
	let nullifier1 = compute_nullifier(&commitment, &spending_key);

	// Should be deterministic
	let nullifier2 = compute_nullifier(&commitment, &spending_key);
	assert_eq!(nullifier1.0, nullifier2.0);
}

#[test]
fn test_strong_types_prevent_confusion() {
	let commitment = Commitment(Bn254Fr::from(123u64));
	let nullifier = Nullifier(Bn254Fr::from(456u64));
	let spending_key = SpendingKey(Bn254Fr::from(789u64));

	// Strong types ensure we can't accidentally pass wrong types
	let _ = compute_nullifier(&commitment, &spending_key);

	// Can still access underlying values when needed
	assert_eq!(commitment.0, Bn254Fr::from(123u64));
	assert_eq!(nullifier.0, Bn254Fr::from(456u64));
	assert_eq!(spending_key.0, Bn254Fr::from(789u64));
}

#[test]
fn test_deep_merkle_tree() {
	// Test with deeper tree (4 levels)
	let leaf = Commitment(Bn254Fr::from(123u64));
	let siblings = vec![
		Bn254Fr::from(456u64),
		Bn254Fr::from(789u64),
		Bn254Fr::from(101u64),
		Bn254Fr::from(202u64),
	];
	let indices = vec![false, true, false, true];

	let root = compute_merkle_root(&leaf, &siblings, &indices);
	assert!(verify_merkle_proof(&leaf, &siblings, &indices, &root));

	// Wrong indices should fail
	let wrong_indices = vec![true, false, true, false];
	assert!(!verify_merkle_proof(
		&leaf,
		&siblings,
		&wrong_indices,
		&root
	));
}

#[test]
fn test_empty_tree_root_consistency() {
	// Empty tree root should be consistent across calls
	let root1 = compute_empty_root(DEFAULT_TREE_DEPTH);
	let root2 = compute_empty_root(DEFAULT_TREE_DEPTH);
	assert_eq!(root1, root2);

	// Different depths should produce different roots
	let root3 = compute_empty_root(DEFAULT_TREE_DEPTH + 1);
	assert_ne!(root1, root3);
}

#[test]
fn test_hash_function_consistency() {
	// Test that hash functions are consistent
	let a = Bn254Fr::from(1u64);
	let b = Bn254Fr::from(2u64);

	let hash1 = poseidon_hash_2(&[a, b]);
	let hash2 = poseidon_hash_2(&[a, b]);
	assert_eq!(hash1, hash2);

	// Different order should produce different hash
	let hash3 = poseidon_hash_2(&[b, a]);
	assert_ne!(hash1, hash3);
}

#[test]
fn test_multiple_assets() {
	// Test notes with different asset IDs
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note_native = Note::new(100, NATIVE_ASSET_ID, owner, blinding);
	let note_asset1 = Note::new(100, 1, owner, blinding);
	let note_asset2 = Note::new(100, 2, owner, blinding);

	// Different asset IDs should produce different commitments
	assert_ne!(note_native.commitment().0, note_asset1.commitment().0);
	assert_ne!(note_native.commitment().0, note_asset2.commitment().0);
	assert_ne!(note_asset1.commitment().0, note_asset2.commitment().0);
}

#[test]
fn test_zero_value_notes() {
	// Test that zero-value notes work correctly
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let note = Note::new(0, NATIVE_ASSET_ID, owner, blinding);
	assert_eq!(note.value_u64(), Some(0));

	let commitment = note.commitment();
	assert_ne!(
		commitment.0,
		Bn254Fr::from(0u64),
		"Even zero-value notes have non-zero commitments"
	);
}

#[test]
fn test_constants() {
	// Verify important constants
	assert_eq!(NATIVE_ASSET_ID, 0);
	assert_eq!(DEFAULT_TREE_DEPTH, 20);
}
