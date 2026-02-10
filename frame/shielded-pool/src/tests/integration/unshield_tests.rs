//! Unshield operation tests
//!
//! Tests for withdrawing tokens from the shielded pool to public accounts.

use crate::tests::helpers::*;
use crate::{Error, Event, mock::*};
use frame_support::{BoundedVec, assert_noop, assert_ok, pallet_prelude::ConstU32};

#[test]
fn unshield_fails_unknown_root() {
	new_test_ext().execute_with(|| {
		// Use a root that is definitely not in historic roots (not genesis [0u8; 32])
		let merkle_root = [255u8; 32];
		let nullifier = sample_nullifier();
		let amount = 500u128;
		let recipient = 2;
		let proof: BoundedVec<u8, ConstU32<512>> = vec![1u8; 64].try_into().unwrap();

		assert_noop!(
			ShieldedPool::unshield(
				RuntimeOrigin::signed(1),
				proof,
				merkle_root,
				nullifier,
				0, // native asset
				amount,
				recipient,
			),
			Error::<Test>::UnknownMerkleRoot
		);
	});
}

#[test]
fn unshield_fails_nullifier_reuse() {
	new_test_ext().execute_with(|| {
		// First, do a shield to establish a known root and pool balance
		let commitment = sample_commitment();
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0, // native asset
			1000u128,
			commitment,
			sample_encrypted_memo(),
		));

		let merkle_root = crate::PoseidonRoot::<Test>::get();

		// Mark nullifier as used (value is block number)
		let nullifier = sample_nullifier();
		crate::NullifierSet::<Test>::insert(nullifier, 1u64);

		let amount = 500u128;
		let recipient = 2;
		let proof: BoundedVec<u8, ConstU32<512>> = vec![1u8; 64].try_into().unwrap();

		assert_noop!(
			ShieldedPool::unshield(
				RuntimeOrigin::signed(1),
				proof,
				merkle_root,
				nullifier,
				0, // native asset
				amount,
				recipient,
			),
			Error::<Test>::NullifierAlreadyUsed
		);
	});
}

#[test]
fn unshield_fails_insufficient_pool_balance() {
	new_test_ext().execute_with(|| {
		// First, do a shield to establish a known root
		let commitment = sample_commitment();
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0, // native asset
			1000u128,
			commitment,
			sample_encrypted_memo(),
		));

		let merkle_root = crate::PoseidonRoot::<Test>::get();
		let nullifier = sample_nullifier();
		let amount = 5000u128; // More than pool balance (1000)
		let recipient = 2;
		let proof: BoundedVec<u8, ConstU32<512>> = vec![1u8; 64].try_into().unwrap();

		assert_noop!(
			ShieldedPool::unshield(
				RuntimeOrigin::signed(1),
				proof,
				merkle_root,
				nullifier,
				0, // native asset
				amount,
				recipient,
			),
			Error::<Test>::InsufficientPoolBalance,
		);
	});
}

#[test]
fn unshield_works() {
	new_test_ext().execute_with(|| {
		// First, do a shield
		let commitment = sample_commitment();
		let shield_amount = 1000u128;
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0, // native asset
			shield_amount,
			commitment,
			sample_encrypted_memo(),
		));

		let merkle_root = crate::PoseidonRoot::<Test>::get();
		let nullifier = sample_nullifier();
		let unshield_amount = 500u128;
		let recipient = 2;
		let recipient_initial = Balances::free_balance(recipient);
		let proof: BoundedVec<u8, ConstU32<512>> = vec![1u8; 64].try_into().unwrap();

		assert_ok!(ShieldedPool::unshield(
			RuntimeOrigin::signed(1),
			proof,
			merkle_root,
			nullifier,
			0, // native asset
			unshield_amount,
			recipient,
		));

		// Check recipient received funds
		assert_eq!(
			Balances::free_balance(recipient),
			recipient_initial + unshield_amount
		);

		// Check pool balance decreased
		assert_eq!(
			crate::PoolBalance::<Test>::get(),
			shield_amount - unshield_amount
		);

		// Check nullifier is now used
		assert!(crate::NullifierSet::<Test>::contains_key(nullifier));

		// Check event
		System::assert_has_event(
			Event::Unshielded {
				nullifier,
				amount: unshield_amount,
				recipient,
			}
			.into(),
		);
	});
}
