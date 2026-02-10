//! Merkle Tree Structure Deep Dive Tests
//!
//! These tests provide a comprehensive understanding of how the Poseidon
//! Merkle tree is constructed in the shielded pool. They serve as both
//! validation and documentation of the tree building algorithm.
//!
//! ## What You'll Learn:
//! - How leaves are hashed into parents level by level
//! - How zero hashes are used for padding odd-numbered nodes
//! - How the tree continues to the configured depth (20)
//! - The exact Poseidon hash values at each level
//!
//! ## Test Organization:
//! 1. Core Validation Tests: Verify correctness for various leaf counts
//! 2. Manual Computation Tests: Step-by-step root calculation
//! 3. Debug/Investigation Tests: Detailed logging for troubleshooting

use crate::infrastructure::merkle_tree::{compute_root_from_leaves_poseidon, hash_pair_poseidon};

// ============================================================================
// SECTION 1: Core Validation Tests
// ============================================================================

#[test]
fn empty_tree_returns_zero() {
	let leaves: Vec<[u8; 32]> = vec![];
	let root = compute_root_from_leaves_poseidon::<20>(&leaves);

	assert_eq!(root, [0u8; 32], "Empty tree should return all zeros");
}

#[test]
fn single_leaf_produces_deterministic_root() {
	let leaf = [42u8; 32];

	// Multiple calls should produce identical roots
	let root1 = compute_root_from_leaves_poseidon::<20>(&[leaf]);
	let root2 = compute_root_from_leaves_poseidon::<20>(&[leaf]);
	let root3 = compute_root_from_leaves_poseidon::<20>(&[leaf]);

	assert_eq!(root1, root2);
	assert_eq!(root2, root3);
	assert_ne!(root1, [0u8; 32], "Single leaf root should be non-zero");
}

#[test]
fn two_leaves_no_padding_required() {
	let leaf0 = [10u8; 32];
	let leaf1 = [20u8; 32];
	let leaves = vec![leaf0, leaf1];

	let root = compute_root_from_leaves_poseidon::<20>(&leaves);

	assert_ne!(root, [0u8; 32], "Two leaves root should be non-zero");

	// Manually compute to verify
	let zero_hashes = compute_zero_hashes();

	// Level 0: hash(leaf0, leaf1) = parent (no padding needed)
	let parent = hash_pair_poseidon(&leaf0, &leaf1);

	// Continue hashing with zeros to depth 20
	let mut expected = parent;
	for zh in &zero_hashes[1..20] {
		expected = hash_pair_poseidon(&expected, zh);
	}

	assert_eq!(
		root, expected,
		"Computed root should match manual calculation"
	);
}

#[test]
fn three_leaves_requires_padding() {
	let leaf0 = [10u8; 32];
	let leaf1 = [20u8; 32];
	let leaf2 = [30u8; 32];
	let leaves = vec![leaf0, leaf1, leaf2];

	let root = compute_root_from_leaves_poseidon::<20>(&leaves);

	assert_ne!(root, [0u8; 32]);

	// Manual computation showing padding
	let zero_hashes = compute_zero_hashes();

	// Level 0: 3 leaves → needs padding to 4
	// parent0 = hash(leaf0, leaf1)
	// parent1 = hash(leaf2, zero[0])  ← padding with zero hash
	let parent0 = hash_pair_poseidon(&leaf0, &leaf1);
	let parent1 = hash_pair_poseidon(&leaf2, &zero_hashes[0]);

	// Level 1: 2 parents → 1 grandparent
	let grandparent = hash_pair_poseidon(&parent0, &parent1);

	// Continue to depth 20 (from level 2)
	let mut expected = grandparent;
	for zh in &zero_hashes[2..20] {
		expected = hash_pair_poseidon(&expected, zh);
	}

	assert_eq!(root, expected, "Three leaves computation should match");
}

#[test]
fn four_leaves_power_of_two() {
	let leaves: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

	let root = compute_root_from_leaves_poseidon::<20>(&leaves);

	assert_ne!(root, [0u8; 32]);

	// Manual computation for perfect binary tree (power of 2)
	let zero_hashes = compute_zero_hashes();

	// Level 0: 4 leaves → 2 parents (no padding)
	let p0 = hash_pair_poseidon(&leaves[0], &leaves[1]);
	let p1 = hash_pair_poseidon(&leaves[2], &leaves[3]);

	// Level 1: 2 parents → 1 grandparent
	let gp = hash_pair_poseidon(&p0, &p1);

	// Continue to depth 20
	let mut expected = gp;
	for zh in &zero_hashes[2..20] {
		expected = hash_pair_poseidon(&expected, zh);
	}

	assert_eq!(root, expected, "Four leaves should form perfect subtree");
}

#[test]
fn five_leaves_multiple_padding_levels() {
	let leaves: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];

	let root = compute_root_from_leaves_poseidon::<20>(&leaves);
	assert_ne!(root, [0u8; 32]);

	let zero_hashes = compute_zero_hashes();

	// Level 0: 5 leaves → pad to 6 → 3 parents
	let p0 = hash_pair_poseidon(&leaves[0], &leaves[1]);
	let p1 = hash_pair_poseidon(&leaves[2], &leaves[3]);
	let p2 = hash_pair_poseidon(&leaves[4], &zero_hashes[0]); // padded

	// Level 1: 3 parents → pad to 4 → 2 grandparents
	let gp0 = hash_pair_poseidon(&p0, &p1);
	let gp1 = hash_pair_poseidon(&p2, &zero_hashes[1]); // padded

	// Level 2: 2 grandparents → 1 great-grandparent
	let ggp = hash_pair_poseidon(&gp0, &gp1);

	// Continue to depth 20
	let mut expected = ggp;
	for zh in &zero_hashes[3..20] {
		expected = hash_pair_poseidon(&expected, zh);
	}

	assert_eq!(root, expected, "Five leaves with multi-level padding");
}

// ============================================================================
// SECTION 2: Zero Hashes Understanding
// ============================================================================

#[test]
fn zero_hashes_are_deterministic() {
	// Zero hashes should be computed consistently
	let zh1 = compute_zero_hashes();
	let zh2 = compute_zero_hashes();

	for i in 0..=20 {
		assert_eq!(zh1[i], zh2[i], "Zero hash mismatch at level {i}");
	}
}

#[test]
fn zero_hash_structure() {
	let zero_hashes = compute_zero_hashes();

	// Level 0: all zeros (empty leaf)
	assert_eq!(zero_hashes[0], [0u8; 32]);

	// Each level is hash(prev, prev)
	for i in 1..=20 {
		let expected = hash_pair_poseidon(&zero_hashes[i - 1], &zero_hashes[i - 1]);
		assert_eq!(
			zero_hashes[i],
			expected,
			"Zero hash at level {} should be hash(zero[{}], zero[{}])",
			i,
			i - 1,
			i - 1
		);
	}

	// All zero hashes should be unique (no collisions in first 20 levels)
	for i in 0..20 {
		assert_ne!(
			zero_hashes[i],
			zero_hashes[i + 1],
			"Zero hashes at consecutive levels should differ"
		);
	}
}

// ============================================================================
// SECTION 3: Different Tree Depths
// ============================================================================

#[test]
fn different_depths_produce_different_roots() {
	let leaves = vec![[1u8; 32], [2u8; 32]];

	let root_depth_5 = compute_root_from_leaves_poseidon::<5>(&leaves);
	let root_depth_10 = compute_root_from_leaves_poseidon::<10>(&leaves);
	let root_depth_20 = compute_root_from_leaves_poseidon::<20>(&leaves);

	// Different depths should produce different roots
	assert_ne!(root_depth_5, root_depth_10);
	assert_ne!(root_depth_10, root_depth_20);
	assert_ne!(root_depth_5, root_depth_20);
}

#[test]
fn root_changes_with_more_leaves() {
	let leaf0 = [1u8; 32];
	let leaf1 = [2u8; 32];
	let leaf2 = [3u8; 32];

	let root1 = compute_root_from_leaves_poseidon::<20>(&[leaf0]);
	let root2 = compute_root_from_leaves_poseidon::<20>(&[leaf0, leaf1]);
	let root3 = compute_root_from_leaves_poseidon::<20>(&[leaf0, leaf1, leaf2]);

	// Adding leaves should change the root
	assert_ne!(root1, root2);
	assert_ne!(root2, root3);
	assert_ne!(root1, root3);
}

// ============================================================================
// SECTION 4: Debug/Investigation Tests (run with --nocapture)
// ============================================================================

#[test]
#[ignore] // Run with: cargo test --lib investigate_tree_construction -- --ignored --nocapture
fn investigate_tree_construction() {
	println!("\n🌳 MERKLE TREE CONSTRUCTION INVESTIGATION\n");
	println!("This test shows step-by-step how a Merkle tree is built with Poseidon.\n");

	// Use 3 distinct leaves for visibility
	let leaves = vec![[0x01; 32], [0x02; 32], [0x03; 32]];

	println!("📊 Input: {} leaves", leaves.len());
	for (i, leaf) in leaves.iter().enumerate() {
		println!("  Leaf[{}]: {}", i, hex_short(leaf));
	}
	println!();

	// Precompute zero hashes
	let zero_hashes = compute_zero_hashes();
	println!("🔢 Zero Hashes (for padding):");
	println!("  zero[0]: {} (empty leaf)", hex_short(&zero_hashes[0]));
	for (i, zh) in zero_hashes.iter().enumerate().take(4).skip(1) {
		println!("  zero[{i}]: {}", hex_short(zh));
	}
	println!("  ... (continuing to level 20)");
	println!("  zero[20]: {}", hex_short(&zero_hashes[20]));
	println!();

	// Manual level-by-level construction
	println!("🧮 Building tree level by level:\n");

	let mut current_level = leaves.clone();
	let mut level_num = 0;

	while current_level.len() > 1 || level_num < 20 {
		println!("Level {}: {} nodes", level_num, current_level.len());

		// Pad if odd
		if current_level.len() % 2 != 0 {
			current_level.push(zero_hashes[level_num]);
			println!("  ├─ Padded with zero[{level_num}]");
		}

		// Hash pairs
		let mut next_level = Vec::new();
		for i in (0..current_level.len()).step_by(2) {
			let left = current_level[i];
			let right = current_level[i + 1];
			let hash = hash_pair_poseidon(&left, &right);
			next_level.push(hash);

			println!(
				"  ├─ hash({}, {}) = {}",
				hex_short(&left),
				hex_short(&right),
				hex_short(&hash)
			);
		}

		current_level = next_level;
		level_num += 1;

		// If we reached 1 node, continue hashing with zeros to depth
		if current_level.len() == 1 && level_num < 20 {
			println!();
			println!("  ⚡ Reached single node at level {level_num}, continuing to depth 20...\n");

			let mut root = current_level[0];
			for (remaining_level, zh) in zero_hashes.iter().enumerate().take(20).skip(level_num) {
				root = hash_pair_poseidon(&root, zh);

				if remaining_level < level_num + 2 || remaining_level >= 19 {
					println!(
						"Level {}: hash({}, zero[{}]) = {}",
						remaining_level,
						hex_short(&root),
						remaining_level,
						hex_short(&root)
					);
				} else if remaining_level == level_num + 2 {
					println!("  ... (continuing to level 19)");
				}
			}
			current_level = vec![root];
			break;
		}

		println!();
	}

	let manual_root = current_level[0];

	// Compare with function
	let function_root = compute_root_from_leaves_poseidon::<20>(&leaves);

	println!("\n📊 RESULTS:");
	println!("┌─────────────────────────────────────────────────────┐");
	println!("│ Manual:   {} │", hex_full(&manual_root));
	println!("│ Function: {} │", hex_full(&function_root));
	println!("└─────────────────────────────────────────────────────┘");

	assert_eq!(manual_root, function_root);
	println!("\n✅ Manual construction matches compute_root_from_leaves_poseidon\n");
}

#[test]
#[ignore] // Run with: cargo test --lib print_hash_examples -- --ignored --nocapture
fn print_hash_examples() {
	println!("\n🔬 POSEIDON HASH EXAMPLES\n");
	println!("These hash values can be compared with TypeScript/Circom implementations.\n");

	// Example 1: Simple values
	println!("Example 1: Simple values");
	let left = [0x01; 32];
	let right = [0x02; 32];
	let hash = hash_pair_poseidon(&left, &right);

	println!("  left:  {}", hex_full(&left));
	println!("  right: {}", hex_full(&right));
	println!("  hash:  {}", hex_full(&hash));
	println!();

	// Example 2: Zero hashes
	println!("Example 2: First 5 zero hashes");
	let zero_hashes = compute_zero_hashes();
	for (i, zh) in zero_hashes.iter().enumerate().take(5) {
		println!("  zero[{i}]: {}", hex_full(zh));
	}
	println!();

	// Example 3: Single leaf tree
	println!("Example 3: Tree with single leaf [0x42, 0x42, ...]");
	let leaf = [0x42; 32];
	let root = compute_root_from_leaves_poseidon::<20>(&[leaf]);
	println!("  leaf: {}", hex_full(&leaf));
	println!("  root: {}", hex_full(&root));
	println!();
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute zero hashes up to level 20
fn compute_zero_hashes() -> [[u8; 32]; 21] {
	let mut zero_hashes = [[0u8; 32]; 21];
	zero_hashes[0] = [0u8; 32];

	for i in 1..=20 {
		zero_hashes[i] = hash_pair_poseidon(&zero_hashes[i - 1], &zero_hashes[i - 1]);
	}

	zero_hashes
}

/// Format hash as hex (first 16 chars)
fn hex_short(hash: &[u8; 32]) -> String {
	hash.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Format hash as full hex string
fn hex_full(hash: &[u8; 32]) -> String {
	hash.iter().map(|b| format!("{b:02x}")).collect()
}
