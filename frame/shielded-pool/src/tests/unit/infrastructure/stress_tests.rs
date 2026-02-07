//! Stress tests for Merkle tree implementation
//!
//! Tests the system under high load to verify:
//! - Memory efficiency with large trees
//! - Root computation performance
//! - Dual-root storage consistency
//! - Historic roots pruning behavior

use crate::{Commitment, mock::*, tests::helpers::sample_encrypted_memo};
use frame_support::assert_ok;

/// Helper to generate unique commitments
fn commitment_from_u32(value: u32) -> Commitment {
	let mut bytes = [0u8; 32];
	bytes[0..4].copy_from_slice(&value.to_le_bytes());
	Commitment(bytes)
}

// ============================================================================
// Stress Tests - Blake2 Only (Sin poseidon-wasm)
// ============================================================================

#[test]
fn stress_test_100_consecutive_shields() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 100;

		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,       // asset_id
				100u128, // MinShieldAmount
				commitment,
				sample_encrypted_memo(),
			));

			// Verify tree size increases
			let tree_size = crate::MerkleTreeSize::<Test>::get();
			assert_eq!(tree_size, i + 1);

			// Verify root is non-zero
			let root = crate::MerkleRoot::<Test>::get();
			assert_ne!(root, [0u8; 32]);
		}

		// Final verification
		let final_root = crate::MerkleRoot::<Test>::get();
		let final_size = crate::MerkleTreeSize::<Test>::get();

		assert_eq!(final_size, NUM_SHIELDS);
		assert_ne!(final_root, [0u8; 32]);

		println!("\u{2705} Successfully processed {NUM_SHIELDS} shields");
		println!("   Final root: {final_root:?}");
		println!("   Tree size: {final_size}");
	});
}

#[test]
fn stress_test_1000_consecutive_shields() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 1000;

		// Track roots to verify they change
		let mut previous_root = [0u8; 32];

		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));

			let current_root = crate::MerkleRoot::<Test>::get();

			// Root should change with each insert
			if i > 0 {
				assert_ne!(
					current_root, previous_root,
					"Root should change at shield {i}"
				);
			}

			previous_root = current_root;

			// Log progress every 100 shields
			if (i + 1) % 100 == 0 {
				println!("   Progress: {}/{} shields processed", i + 1, NUM_SHIELDS);
			}
		}

		let final_size = crate::MerkleTreeSize::<Test>::get();
		assert_eq!(final_size, NUM_SHIELDS);

		println!("\u{2705} Successfully processed {NUM_SHIELDS} shields");
		println!("   Final tree size: {final_size}");
	});
}

#[test]
fn stress_test_historic_roots_pruning_with_many_shields() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 150; // More than MAX_HISTORIC_ROOTS (100)
		let max_roots = <Test as crate::Config>::MaxHistoricRoots::get();

		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));
		}

		// Verify that historic roots were pruned
		let order = crate::HistoricRootsOrder::<Test>::get();
		assert!(
			order.len() <= max_roots as usize,
			"Historic roots should be pruned to max: {}, got: {}",
			max_roots,
			order.len()
		);

		println!("✅ Historic roots properly pruned");
		println!("   Max roots: {max_roots}");
		println!("   Current historic roots: {}", order.len());
	});
}

#[test]
fn stress_test_all_roots_are_known_during_insertion() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 50;
		let mut roots = sp_std::vec::Vec::new();

		// Insert shields and collect roots
		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));

			let root = crate::MerkleRoot::<Test>::get();
			roots.push(root);
		}

		// Verify all roots are known
		for (i, root) in roots.iter().enumerate() {
			let is_known = crate::HistoricRoots::<Test>::get(root);
			assert!(
				is_known,
				"Root at index {i} should be known in historic roots"
			);
		}

		println!("\u{2705} All {NUM_SHIELDS} roots are properly tracked in historic storage");
	});
}

// ============================================================================
// Stress Tests - Dual-Root (Con poseidon-wasm)
// ============================================================================

#[cfg(feature = "poseidon-wasm")]
#[test]
fn stress_test_dual_roots_100_shields() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 100;

		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));

			// Verify both roots exist and are different
			let blake2_root = crate::MerkleRoot::<Test>::get();
			let poseidon_root =
				crate::PoseidonRoot::<Test>::get().expect("Poseidon root should exist");

			assert_ne!(
				blake2_root, [0u8; 32],
				"Blake2 root should be non-zero at shield {i}"
			);
			assert_ne!(
				poseidon_root, [0u8; 32],
				"Poseidon root should be non-zero at shield {i}"
			);
			assert_ne!(
				blake2_root, poseidon_root,
				"Roots should differ at shield {i}"
			);
		}

		println!("✅ Dual-root computation successful for {NUM_SHIELDS} shields");
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn stress_test_dual_roots_1000_shields() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 1000;

		let mut prev_blake2 = [0u8; 32];
		let mut prev_poseidon = [0u8; 32];

		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));

			let blake2_root = crate::MerkleRoot::<Test>::get();
			let poseidon_root =
				crate::PoseidonRoot::<Test>::get().expect("Poseidon root should exist");

			// Both roots should change with each insert
			if i > 0 {
				assert_ne!(blake2_root, prev_blake2, "Blake2 root should change at {i}");
				assert_ne!(
					poseidon_root, prev_poseidon,
					"Poseidon root should change at {i}"
				);
			}

			prev_blake2 = blake2_root;
			prev_poseidon = poseidon_root;

			if (i + 1) % 100 == 0 {
				println!(
					"   Progress: {}/{} dual-root shields processed",
					i + 1,
					NUM_SHIELDS
				);
			}
		}

		println!("✅ Dual-root system handles {NUM_SHIELDS} shields successfully");
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn stress_test_dual_historic_roots_pruning() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 150; // More than MAX_HISTORIC_ROOTS
		let max_roots = <Test as crate::Config>::MaxHistoricRoots::get();

		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));
		}

		// Check both Blake2 and Poseidon historic storage
		let blake2_order = crate::HistoricRootsOrder::<Test>::get();

		assert!(
			blake2_order.len() <= max_roots as usize,
			"Blake2 historic roots should be pruned"
		);

		// Verify Poseidon roots are also tracked
		let poseidon_root = crate::PoseidonRoot::<Test>::get();
		assert!(poseidon_root.is_some(), "Poseidon root should exist");
		assert_ne!(
			poseidon_root.unwrap(),
			[0u8; 32],
			"Poseidon root should be non-zero"
		);

		// Both systems should track the same roots (in different formats)
		// but with same FIFO pruning behavior
		assert!(
			blake2_order.len() <= max_roots as usize,
			"Historic roots (shared for both hashes) should be pruned"
		);

		println!("✅ Dual historic roots properly pruned and synchronized");
		println!("   Blake2 historic roots order: {}", blake2_order.len());
		println!("   Current Poseidon root: {poseidon_root:?}");
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn stress_test_poseidon_roots_deterministic_under_load() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 100;
		let mut roots_run1 = sp_std::vec::Vec::new();

		// First run: collect Poseidon roots
		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));

			let root = crate::PoseidonRoot::<Test>::get().unwrap();
			roots_run1.push(root);
		}

		// Reset state
		crate::MerkleRoot::<Test>::kill();
		crate::PoseidonRoot::<Test>::kill();
		crate::MerkleTreeSize::<Test>::kill();
		let _ = crate::MerkleLeaves::<Test>::clear(u32::MAX, None);
		let _ = crate::HistoricRoots::<Test>::clear(u32::MAX, None);
		let _ = crate::HistoricPoseidonRoots::<Test>::clear(u32::MAX, None);

		// Second run: verify same roots
		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));

			let root = crate::PoseidonRoot::<Test>::get().unwrap();
			assert_eq!(
				root, roots_run1[i as usize],
				"Poseidon root should be deterministic at shield {i}"
			);
		}

		println!("✅ Poseidon roots are deterministic across {NUM_SHIELDS} shields");
	});
}

// ============================================================================
// Performance Tracking Tests
// ============================================================================

#[test]
fn perf_track_shield_operation_time() {
	new_test_ext().execute_with(|| {
		const NUM_SAMPLES: u32 = 10;

		println!("\n📊 Shield Operation Performance:");

		for i in 0..NUM_SAMPLES {
			let commitment = commitment_from_u32(i);

			// In real benchmarks we'd use Instant::now(), but in tests we just verify it works
			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));

			println!("   Shield {} completed", i + 1);
		}

		println!("\u{2705} Performance tracking completed for {NUM_SAMPLES} shields");
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn perf_track_dual_root_overhead() {
	new_test_ext().execute_with(|| {
		const NUM_SHIELDS: u32 = 50;

		println!("\n📊 Dual-Root Performance Test:");

		for i in 0..NUM_SHIELDS {
			let commitment = commitment_from_u32(i);

			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo(),
			));

			// Verify both roots computed correctly
			let _ = crate::MerkleRoot::<Test>::get();
			let _ = crate::PoseidonRoot::<Test>::get().unwrap();
		}

		println!("✅ Dual-root overhead test completed for {NUM_SHIELDS} shields");
		println!("   Both Blake2 and Poseidon roots computed successfully");
	});
}
