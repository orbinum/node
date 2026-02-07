//! Shield operation tests
//!
//! Tests for depositing public tokens into the shielded pool.

use crate::tests::helpers::*;
use crate::{Error, Event, mock::*};
use frame_support::{assert_noop, assert_ok};

#[test]
fn shield_works() {
	new_test_ext().execute_with(|| {
		let depositor = 1;
		let amount = 1000u128;
		let commitment = sample_commitment();
		let encrypted_memo = sample_encrypted_memo();

		let _initial_balance = Balances::free_balance(depositor);

		// Shield tokens
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(depositor),
			0, // native asset
			amount,
			commitment,
			encrypted_memo.clone(),
		));

		// Check Merkle tree was updated
		assert_eq!(crate::MerkleTreeSize::<Test>::get(), 1);

		// Check memo was stored
		assert_eq!(
			crate::CommitmentMemos::<Test>::get(commitment),
			Some(encrypted_memo.clone())
		);

		// Check event (leaf_index = 0 for first commitment)
		System::assert_has_event(
			Event::Shielded {
				depositor,
				amount,
				commitment,
				encrypted_memo,
				leaf_index: 0,
			}
			.into(),
		);
	});
}

#[test]
fn shield_fails_below_minimum() {
	new_test_ext().execute_with(|| {
		let depositor = 1;
		let amount = 50u128; // Below MinShieldAmount (100)
		let commitment = sample_commitment();
		let encrypted_memo = sample_encrypted_memo();

		assert_noop!(
			ShieldedPool::shield(
				RuntimeOrigin::signed(depositor),
				0, // native asset
				amount,
				commitment,
				encrypted_memo
			),
			Error::<Test>::AmountTooSmall
		);
	});
}

#[test]
fn shield_fails_insufficient_balance() {
	new_test_ext().execute_with(|| {
		let depositor = 1;
		let amount = 10_000_000u128; // More than account has (1_000_000)
		let commitment = sample_commitment();

		assert_noop!(
			ShieldedPool::shield(
				RuntimeOrigin::signed(depositor),
				0, // native asset
				amount,
				commitment,
				sample_encrypted_memo()
			),
			sp_runtime::DispatchError::Arithmetic(sp_runtime::ArithmeticError::Underflow)
		);
	});
}
