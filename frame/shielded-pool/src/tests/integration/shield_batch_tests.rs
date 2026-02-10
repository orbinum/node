//! Tests for shield_batch extrinsic (OPT-1.2 optimization)

use crate::{Commitment, Error, mock::*, tests::helpers::sample_encrypted_memo};
use frame_support::{BoundedVec, assert_noop, assert_ok};

/// Helper to generate unique commitments
fn commitment_from_u32(value: u32) -> Commitment {
	let mut bytes = [0u8; 32];
	bytes[0..4].copy_from_slice(&value.to_le_bytes());
	Commitment(bytes)
}

#[test]
fn shield_batch_works() {
	new_test_ext().execute_with(|| {
		let account = 1;
		let asset_id = 0u32;
		let amount = 100u128; // MinShieldAmount

		// Prepare batch of 5 shields
		let operations: BoundedVec<_, _> = (0..5)
			.map(|i| {
				(
					asset_id,
					amount,
					commitment_from_u32(i),
					sample_encrypted_memo(),
				)
			})
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		// Execute batch
		assert_ok!(ShieldedPool::shield_batch(
			RuntimeOrigin::signed(account),
			operations
		));

		// Verify tree has 5 leaves
		let tree_size = crate::MerkleTreeSize::<Test>::get();
		assert_eq!(tree_size, 5);

		// Verify root is non-zero
		let root = crate::PoseidonRoot::<Test>::get();
		assert_ne!(root, [0u8; 32]);
	});
}

#[test]
fn shield_batch_updates_balances_correctly() {
	new_test_ext().execute_with(|| {
		let account = 1;
		let initial_balance = Balances::free_balance(account);
		let asset_id = 0u32;
		let amount = 100u128;
		let batch_size = 10;

		// Prepare batch
		let operations: BoundedVec<_, _> = (0..batch_size)
			.map(|i| {
				(
					asset_id,
					amount,
					commitment_from_u32(i),
					sample_encrypted_memo(),
				)
			})
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		// Execute batch
		assert_ok!(ShieldedPool::shield_batch(
			RuntimeOrigin::signed(account),
			operations
		));

		// Verify balance deducted correctly
		let final_balance = Balances::free_balance(account);
		let expected_deduction = amount * (batch_size as u128);
		assert_eq!(
			final_balance,
			initial_balance - expected_deduction,
			"Balance should be deducted for all shields"
		);

		// Verify pool balance increased
		let pool_balance = crate::PoolBalance::<Test>::get();
		assert_eq!(pool_balance, expected_deduction);
	});
}

#[test]
fn shield_batch_fails_on_invalid_operation() {
	new_test_ext().execute_with(|| {
		let account = 1;
		let asset_id = 0u32;

		// Create batch with one invalid amount (too small)
		let operations: BoundedVec<_, _> = vec![
			(
				asset_id,
				100u128,
				commitment_from_u32(0),
				sample_encrypted_memo(),
			),
			(
				asset_id,
				1u128,
				commitment_from_u32(1),
				sample_encrypted_memo(),
			), // Too small!
			(
				asset_id,
				100u128,
				commitment_from_u32(2),
				sample_encrypted_memo(),
			),
		]
		.try_into()
		.unwrap();

		// Should fail on second operation
		assert_noop!(
			ShieldedPool::shield_batch(RuntimeOrigin::signed(account), operations),
			Error::<Test>::AmountTooSmall
		);

		// Verify no shields were processed (atomic failure)
		let tree_size = crate::MerkleTreeSize::<Test>::get();
		assert_eq!(
			tree_size, 0,
			"No shields should be processed on batch failure"
		);
	});
}

#[test]
fn shield_batch_respects_max_size() {
	new_test_ext().execute_with(|| {
		let _account = 1;
		let asset_id = 0u32;
		let amount = 100u128;

		// Try to create batch larger than max (20)
		let operations: Vec<_> = (0..21)
			.map(|i| {
				(
					asset_id,
					amount,
					commitment_from_u32(i),
					sample_encrypted_memo(),
				)
			})
			.collect();

		// Should fail to convert to BoundedVec
		type BatchType = BoundedVec<
			(u32, u128, Commitment, crate::FrameEncryptedMemo),
			frame_support::traits::ConstU32<20>,
		>;
		let bounded_result: Result<BatchType, _> = operations.try_into();
		assert!(bounded_result.is_err(), "Should not allow batch > 20");
	});
}

#[test]
fn shield_batch_max_size_works() {
	new_test_ext().execute_with(|| {
		let account = 1;
		let asset_id = 0u32;
		let amount = 100u128;

		// Create batch at max size (20)
		let operations: BoundedVec<_, _> = (0..20)
			.map(|i| {
				(
					asset_id,
					amount,
					commitment_from_u32(i),
					sample_encrypted_memo(),
				)
			})
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		// Should succeed
		assert_ok!(ShieldedPool::shield_batch(
			RuntimeOrigin::signed(account),
			operations
		));

		// Verify all 20 shields processed
		let tree_size = crate::MerkleTreeSize::<Test>::get();
		assert_eq!(tree_size, 20);
	});
}

#[test]
fn shield_batch_processes_unique_commitments() {
	new_test_ext().execute_with(|| {
		let account = 1;
		let asset_id = 0u32;
		let amount = 100u128;

		// Create batch with unique commitments
		let operations: BoundedVec<_, _> = vec![
			(
				asset_id,
				amount,
				commitment_from_u32(0),
				sample_encrypted_memo(),
			),
			(
				asset_id,
				amount,
				commitment_from_u32(1),
				sample_encrypted_memo(),
			),
			(
				asset_id,
				amount,
				commitment_from_u32(2),
				sample_encrypted_memo(),
			),
		]
		.try_into()
		.unwrap();

		assert_ok!(ShieldedPool::shield_batch(
			RuntimeOrigin::signed(account),
			operations
		));

		// All three shields should be processed
		let tree_size = crate::MerkleTreeSize::<Test>::get();
		assert_eq!(tree_size, 3, "All shields processed successfully");
	});
}

#[test]
fn shield_batch_emits_events() {
	new_test_ext().execute_with(|| {
		let account = 1;
		let asset_id = 0u32;
		let amount = 100u128;

		// Create batch of 3
		let operations: BoundedVec<_, _> = (0..3)
			.map(|i| {
				(
					asset_id,
					amount,
					commitment_from_u32(i),
					sample_encrypted_memo(),
				)
			})
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		assert_ok!(ShieldedPool::shield_batch(
			RuntimeOrigin::signed(account),
			operations
		));

		// Verify 3 Shielded events emitted
		let events = System::events();
		let shield_events: Vec<_> = events
			.iter()
			.filter(|e| {
				matches!(
					e.event,
					RuntimeEvent::ShieldedPool(crate::Event::Shielded { .. })
				)
			})
			.collect();

		assert_eq!(shield_events.len(), 3, "Should emit 3 Shielded events");
	});
}

#[test]
fn shield_batch_empty_batch_works() {
	new_test_ext().execute_with(|| {
		let account = 1;
		let operations: BoundedVec<_, _> = vec![].try_into().unwrap();

		// Empty batch should succeed (no-op)
		assert_ok!(ShieldedPool::shield_batch(
			RuntimeOrigin::signed(account),
			operations
		));

		// Verify nothing changed
		let tree_size = crate::MerkleTreeSize::<Test>::get();
		assert_eq!(tree_size, 0);
	});
}
