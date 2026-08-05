//! Storage access — typed wrappers over every `StorageValue` / `StorageMap`.
//!
//! One module per logical domain, one repository struct in each. All functions
//! are static; no instance state. Keeping the raw storage items behind these
//! wrappers means the pallet body never names a `StorageMap` directly, so a
//! layout change stays contained here.

pub mod asset;
pub mod balance;
pub mod commitment;
pub mod merkle;
pub mod nullifier;
pub mod stats;

pub use asset::AssetRepository;
pub use balance::PoolBalanceRepository;
pub use commitment::CommitmentRepository;
pub use merkle::MerkleRepository;
pub use nullifier::NullifierRepository;
pub use stats::PoolStatsRepository;

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, acc, new_test_ext},
		types::{AssetMetadata, Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Nullifier},
	};
	use frame_support::{BoundedVec, pallet_prelude::ConstU32};
	use sp_runtime::AccountId32;

	// ── helpers ───────────────────────────────────────────────────────────────

	fn test_commitment(seed: u8) -> Commitment {
		Commitment::new([seed; 32])
	}

	fn test_nullifier(seed: u8) -> Nullifier {
		Nullifier::new([seed; 32])
	}

	fn test_memo() -> EncryptedMemo {
		EncryptedMemo::from_bytes(&[0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap()
	}

	fn make_asset_metadata(id: u32) -> AssetMetadata<AccountId32, u64> {
		AssetMetadata::new(
			id,
			BoundedVec::try_from(b"Test".to_vec()).unwrap(),
			BoundedVec::try_from(b"TST".to_vec()).unwrap(),
			18,
			0u64,
			acc(1),
		)
	}

	// ── AssetRepository ──────────────────────────────────────────────────────

	#[test]
	fn asset_repo_store_and_get() {
		new_test_ext().execute_with(|| {
			let meta = make_asset_metadata(10);
			AssetRepository::store_asset::<Test>(10, meta);
			let got = AssetRepository::get_asset::<Test>(10).unwrap();
			assert_eq!(got.id, 10);
		});
	}

	#[test]
	fn asset_repo_exists_returns_correct() {
		new_test_ext().execute_with(|| {
			assert!(!AssetRepository::exists::<Test>(99));
			AssetRepository::store_asset::<Test>(99, make_asset_metadata(99));
			assert!(AssetRepository::exists::<Test>(99));
		});
	}

	#[test]
	fn asset_repo_get_none_for_unknown() {
		new_test_ext().execute_with(|| {
			assert!(AssetRepository::get_asset::<Test>(999).is_none());
		});
	}

	#[test]
	fn asset_repo_get_next_id_starts_at_1() {
		new_test_ext().execute_with(|| {
			// genesis sets NextAssetId = 1
			assert_eq!(AssetRepository::get_next_asset_id::<Test>(), 1);
		});
	}

	#[test]
	fn asset_repo_increment_returns_current_then_advances() {
		new_test_ext().execute_with(|| {
			let id0 = AssetRepository::increment_asset_id::<Test>(); // returns 1, stores 2
			assert_eq!(id0, 1);
			let id1 = AssetRepository::increment_asset_id::<Test>(); // returns 2, stores 3
			assert_eq!(id1, 2);
			assert_eq!(AssetRepository::get_next_asset_id::<Test>(), 3);
		});
	}

	#[test]
	fn asset_repo_set_verified_true_and_false() {
		new_test_ext().execute_with(|| {
			AssetRepository::store_asset::<Test>(5, make_asset_metadata(5));
			assert!(AssetRepository::set_verified::<Test>(5, true));
			assert!(AssetRepository::get_asset::<Test>(5).unwrap().is_verified);
			assert!(AssetRepository::set_verified::<Test>(5, false));
			assert!(!AssetRepository::get_asset::<Test>(5).unwrap().is_verified);
		});
	}

	#[test]
	fn asset_repo_set_verified_not_found_returns_false() {
		new_test_ext().execute_with(|| {
			assert!(!AssetRepository::set_verified::<Test>(999, true));
		});
	}

	// ── CommitmentRepository ─────────────────────────────────────────────────

	#[test]
	fn commitment_repo_store_and_get_memo() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x01);
			let memo = test_memo();
			CommitmentRepository::store_memo::<Test>(c, memo.clone());
			assert_eq!(CommitmentRepository::get_memo::<Test>(&c), Some(memo));
		});
	}

	#[test]
	fn commitment_repo_exists_returns_correct() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x02);
			assert!(!CommitmentRepository::exists::<Test>(&c));
			CommitmentRepository::store_memo::<Test>(c, test_memo());
			assert!(CommitmentRepository::exists::<Test>(&c));
		});
	}

	#[test]
	fn commitment_repo_get_memo_none_when_missing() {
		new_test_ext().execute_with(|| {
			assert!(CommitmentRepository::get_memo::<Test>(&test_commitment(0xAA)).is_none());
		});
	}

	// ── MerkleRepository ─────────────────────────────────────────────────────

	#[test]
	fn merkle_repo_poseidon_root_get_and_set() {
		new_test_ext().execute_with(|| {
			let root = [0xBBu8; 32];
			MerkleRepository::set_poseidon_root::<Test>(root);
			assert_eq!(MerkleRepository::get_poseidon_root::<Test>(), root);
		});
	}

	#[test]
	fn merkle_repo_tree_size_zero_on_start() {
		new_test_ext().execute_with(|| {
			assert_eq!(MerkleRepository::get_tree_size::<Test>(), 0);
		});
	}

	#[test]
	fn merkle_repo_tree_size_set() {
		new_test_ext().execute_with(|| {
			MerkleRepository::set_tree_size::<Test>(7);
			assert_eq!(MerkleRepository::get_tree_size::<Test>(), 7);
		});
	}

	#[test]
	fn merkle_repo_insert_and_get_leaf() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x05);
			MerkleRepository::insert_leaf::<Test>(0, c);
			assert_eq!(MerkleRepository::get_leaf::<Test>(0), Some(c));
			assert_eq!(MerkleRepository::get_leaf::<Test>(1), None);
		});
	}

	#[test]
	fn merkle_repo_is_known_root_after_add() {
		new_test_ext().execute_with(|| {
			let root = [0xCCu8; 32];
			assert!(!MerkleRepository::is_known_root::<Test>(&root));
			MerkleRepository::add_historic_poseidon_root::<Test>(root);
			assert!(MerkleRepository::is_known_root::<Test>(&root));
		});
	}

	#[test]
	fn merkle_repo_remove_historic_root() {
		new_test_ext().execute_with(|| {
			let root = [0xDDu8; 32];
			MerkleRepository::add_historic_poseidon_root::<Test>(root);
			assert!(MerkleRepository::is_known_root::<Test>(&root));
			MerkleRepository::remove_poseidon_historic_root::<Test>(&root);
			assert!(!MerkleRepository::is_known_root::<Test>(&root));
		});
	}

	#[test]
	fn merkle_repo_commitment_to_leaf_index_get_set() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0xDE);
			// Before insertion: returns None
			assert_eq!(
				MerkleRepository::get_commitment_leaf_index::<Test>(&c),
				None
			);
			// After set: returns the stored index
			MerkleRepository::set_commitment_leaf_index::<Test>(c, 7);
			assert_eq!(
				MerkleRepository::get_commitment_leaf_index::<Test>(&c),
				Some(7)
			);
			// A different commitment is unaffected
			assert_eq!(
				MerkleRepository::get_commitment_leaf_index::<Test>(&test_commitment(0xAB)),
				None
			);
		});
	}

	#[test]
	fn merkle_repo_find_leaf_index_returns_correct_positions() {
		new_test_ext().execute_with(|| {
			let c0 = test_commitment(0xA1);
			let c1 = test_commitment(0xA2);
			MerkleRepository::insert_leaf::<Test>(0, c0);
			MerkleRepository::set_commitment_leaf_index::<Test>(c0, 0);
			MerkleRepository::insert_leaf::<Test>(1, c1);
			MerkleRepository::set_commitment_leaf_index::<Test>(c1, 1);
			MerkleRepository::set_tree_size::<Test>(2);
			assert_eq!(MerkleRepository::find_leaf_index::<Test>(&c0), Some(0));
			assert_eq!(MerkleRepository::find_leaf_index::<Test>(&c1), Some(1));
			assert_eq!(
				MerkleRepository::find_leaf_index::<Test>(&test_commitment(0xFF)),
				None
			);
		});
	}

	#[test]
	fn merkle_repo_node_get_set_and_missing() {
		new_test_ext().execute_with(|| {
			assert_eq!(MerkleRepository::get_node::<Test>(0, 1, 0), None);
			let node = [0xB1u8; 32];
			MerkleRepository::set_node::<Test>(0, 1, 0, node);
			assert_eq!(MerkleRepository::get_node::<Test>(0, 1, 0), Some(node));
			// Distinct coordinates are independent
			assert_eq!(MerkleRepository::get_node::<Test>(0, 1, 1), None);
			assert_eq!(MerkleRepository::get_node::<Test>(0, 2, 0), None);
			assert_eq!(MerkleRepository::get_node::<Test>(1, 1, 0), None);
		});
	}

	// ── NullifierRepository ──────────────────────────────────────────────────

	#[test]
	fn nullifier_repo_not_used_by_default() {
		new_test_ext().execute_with(|| {
			assert!(!NullifierRepository::is_used::<Test>(&test_nullifier(0x01)));
		});
	}

	#[test]
	fn nullifier_repo_mark_and_check_used() {
		new_test_ext().execute_with(|| {
			let n = test_nullifier(0x02);
			NullifierRepository::mark_as_used::<Test>(n, 42u64);
			assert!(NullifierRepository::is_used::<Test>(&n));
		});
	}

	#[test]
	fn nullifier_repo_get_usage_block() {
		new_test_ext().execute_with(|| {
			let n = test_nullifier(0x03);
			assert!(NullifierRepository::get_usage_block::<Test>(&n).is_none());
			NullifierRepository::mark_as_used::<Test>(n, 100u64);
			assert_eq!(
				NullifierRepository::get_usage_block::<Test>(&n),
				Some(100u64)
			);
		});
	}

	// ── PoolStatsRepository ───────────────────────────────────────────────────

	#[test]
	fn pool_stats_commitments_zero_by_default() {
		new_test_ext().execute_with(|| {
			assert_eq!(
				PoolStatsRepository::get_total_commitments_inserted::<Test>(),
				0
			);
		});
	}

	#[test]
	fn pool_stats_commitments_increments_correctly() {
		new_test_ext().execute_with(|| {
			PoolStatsRepository::increment_commitments_inserted::<Test>();
			PoolStatsRepository::increment_commitments_inserted::<Test>();
			PoolStatsRepository::increment_commitments_inserted::<Test>();
			assert_eq!(
				PoolStatsRepository::get_total_commitments_inserted::<Test>(),
				3
			);
		});
	}

	#[test]
	fn pool_stats_nullifiers_zero_by_default() {
		new_test_ext().execute_with(|| {
			assert_eq!(PoolStatsRepository::get_total_nullifiers_spent::<Test>(), 0);
		});
	}

	#[test]
	fn pool_stats_nullifiers_incremented_by_mark_as_used() {
		new_test_ext().execute_with(|| {
			let n0 = test_nullifier(0xE0);
			let n1 = test_nullifier(0xE1);
			NullifierRepository::mark_as_used::<Test>(n0, 1u64);
			NullifierRepository::mark_as_used::<Test>(n1, 2u64);
			assert_eq!(PoolStatsRepository::get_total_nullifiers_spent::<Test>(), 2);
		});
	}

	// ── PoolBalanceRepository ─────────────────────────────────────────────────

	#[test]
	fn pool_balance_repo_zero_by_default() {
		new_test_ext().execute_with(|| {
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(0), 0u128);
		});
	}

	#[test]
	fn pool_balance_repo_set_and_get() {
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(1, 500u128);
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(1), 500u128);
		});
	}

	#[test]
	fn pool_balance_repo_increase_adds_amount() {
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(2, 100u128);
			PoolBalanceRepository::increase_balance::<Test>(2, 50u128);
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(2), 150u128);
		});
	}

	#[test]
	fn pool_balance_repo_decrease_subtracts_amount() {
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(3, 200u128);
			PoolBalanceRepository::decrease_balance::<Test>(3, 80u128);
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(3), 120u128);
		});
	}

	#[test]
	fn pool_balance_repo_decrease_to_exact_zero() {
		new_test_ext().execute_with(|| {
			// Decrementing by the full balance reaches zero without tripping the
			// `defensive_assert!(balance >= amount)` guard.
			PoolBalanceRepository::set_asset_balance::<Test>(4, 100u128);
			PoolBalanceRepository::decrease_balance::<Test>(4, 100u128);
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(4), 0u128);
		});
	}

	#[test]
	#[cfg(debug_assertions)]
	#[should_panic(expected = "Defensive")]
	fn pool_balance_repo_decrease_below_balance_is_defensive() {
		// An over-decrement (balance < amount) is an accounting bug: the defensive
		// guard trips in test/debug. In production `saturating_sub` still floors at
		// zero, but this path must never be reached under invariant (A).
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(4, 10u128);
			PoolBalanceRepository::decrease_balance::<Test>(4, 100u128);
		});
	}

	fn _suppress_unused(_: ConstU32<10>) {}
}
