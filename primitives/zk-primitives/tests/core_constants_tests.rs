//! Integration tests for core constants

use fp_zk_primitives::core::constants::{
	COMMITMENT_DOMAIN, DEFAULT_TREE_DEPTH, FIELD_ELEMENT_SIZE, MAX_TREE_DEPTH, NATIVE_ASSET_ID,
	NULLIFIER_DOMAIN,
};

#[test]
fn test_default_tree_depth() {
	assert_eq!(DEFAULT_TREE_DEPTH, 20);
	// 2^20 = 1,048,576 leaves (approximately 1 million)
	assert_eq!(1 << DEFAULT_TREE_DEPTH, 1_048_576);
}

#[test]
fn test_max_tree_depth() {
	assert_eq!(MAX_TREE_DEPTH, 32);
	// 2^32 = 4,294,967,296 leaves
	assert_eq!(1u64 << MAX_TREE_DEPTH, 4_294_967_296);
}

#[test]
fn test_tree_depth_relationship() {
	// Max depth should be greater than default depth
	// Note: This is a compile-time constant check, validated at build time
	const _: () = assert!(MAX_TREE_DEPTH > DEFAULT_TREE_DEPTH);
}

#[test]
fn test_native_asset_id() {
	assert_eq!(NATIVE_ASSET_ID, 0);
}

#[test]
fn test_field_element_size() {
	assert_eq!(FIELD_ELEMENT_SIZE, 32);
	// 32 bytes = 256 bits
	assert_eq!(FIELD_ELEMENT_SIZE * 8, 256);
}

#[test]
fn test_commitment_domain() {
	assert_eq!(COMMITMENT_DOMAIN, "orbinum-commitment-v1");
	assert!(!COMMITMENT_DOMAIN.is_empty());
	assert!(COMMITMENT_DOMAIN.starts_with("orbinum-"));
	assert!(COMMITMENT_DOMAIN.ends_with("-v1"));
}

#[test]
fn test_nullifier_domain() {
	assert_eq!(NULLIFIER_DOMAIN, "orbinum-nullifier-v1");
	assert!(!NULLIFIER_DOMAIN.is_empty());
	assert!(NULLIFIER_DOMAIN.starts_with("orbinum-"));
	assert!(NULLIFIER_DOMAIN.ends_with("-v1"));
}

#[test]
fn test_domain_separators_are_different() {
	// Domain separators should be unique to prevent hash collisions
	assert_ne!(COMMITMENT_DOMAIN, NULLIFIER_DOMAIN);
}

#[test]
fn test_constants_are_reasonable() {
	// Sanity checks for constant values - validated at compile time
	const _: () = {
		assert!(DEFAULT_TREE_DEPTH > 0);
		assert!(MAX_TREE_DEPTH > 0);
		assert!(FIELD_ELEMENT_SIZE > 0);
		assert!(DEFAULT_TREE_DEPTH < 64);
		assert!(MAX_TREE_DEPTH < 64);
	};

	// Field element size should match BN254
	assert_eq!(FIELD_ELEMENT_SIZE, 32);
}

#[test]
fn test_tree_capacity() {
	// Verify tree can hold expected number of leaves
	let default_capacity = 1usize << DEFAULT_TREE_DEPTH;
	let max_capacity = 1usize << MAX_TREE_DEPTH;

	assert!(default_capacity > 1_000_000); // At least 1 million
	assert!(max_capacity > 4_000_000_000); // At least 4 billion
}
