//! Private transfer operation tests
//!
//! Tests for transferring tokens privately within the shielded pool.

use crate::tests::helpers::*;
use crate::{Commitment, Error, Event, Nullifier, mock::*};
use frame_support::{BoundedVec, assert_noop, assert_ok, pallet_prelude::ConstU32};

#[test]
fn private_transfer_works() {
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

		// Get the current root
		let merkle_root = crate::PoseidonRoot::<Test>::get();

		let nullifiers: BoundedVec<Nullifier, ConstU32<2>> =
			vec![sample_nullifier()].try_into().unwrap();
		let new_commitments: BoundedVec<Commitment, ConstU32<2>> =
			vec![Commitment([3u8; 32]), Commitment([4u8; 32])]
				.try_into()
				.unwrap();
		let proof: BoundedVec<u8, ConstU32<512>> = vec![1u8; 64].try_into().unwrap();

		// Should succeed with mock verifier
		let encrypted_memos: BoundedVec<_, ConstU32<2>> = vec![
			sample_encrypted_memo_with_seed(1),
			sample_encrypted_memo_with_seed(2),
		]
		.try_into()
		.unwrap();

		assert_ok!(ShieldedPool::private_transfer(
			RuntimeOrigin::signed(1),
			proof,
			merkle_root,
			nullifiers.clone(),
			new_commitments.clone(),
			encrypted_memos.clone(),
		));

		// Check nullifier is now used
		assert!(crate::NullifierSet::<Test>::contains_key(nullifiers[0]));

		// Check new commitments were added to tree
		// Initial shield added 1 leaf, now we have 3 (1 + 2 new)
		assert_eq!(crate::MerkleTreeSize::<Test>::get(), 3);

		// Check event
		System::assert_has_event(
			Event::PrivateTransfer {
				nullifiers,
				commitments: new_commitments,
				encrypted_memos,
				leaf_indices: vec![1u32, 2u32].try_into().unwrap(),
			}
			.into(),
		);
	});
}

#[test]
fn private_transfer_fails_unknown_root() {
	new_test_ext().execute_with(|| {
		// Use a root that is definitely not in historic roots (not genesis [0u8; 32])
		let merkle_root = [255u8; 32];
		let nullifiers: BoundedVec<Nullifier, ConstU32<2>> =
			vec![sample_nullifier()].try_into().unwrap();
		let commitments: BoundedVec<Commitment, ConstU32<2>> =
			vec![sample_commitment()].try_into().unwrap();
		let proof: BoundedVec<u8, ConstU32<512>> = vec![1u8; 64].try_into().unwrap();

		// Should fail - root not known
		let encrypted_memos: BoundedVec<_, ConstU32<2>> =
			vec![sample_encrypted_memo()].try_into().unwrap();

		assert_noop!(
			ShieldedPool::private_transfer(
				RuntimeOrigin::signed(1),
				proof,
				merkle_root,
				nullifiers,
				commitments,
				encrypted_memos,
			),
			Error::<Test>::UnknownMerkleRoot
		);
	});
}

#[test]
fn private_transfer_fails_nullifier_reuse() {
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

		// Get the current root
		let merkle_root = crate::PoseidonRoot::<Test>::get();

		// Mark a nullifier as used (value is block number)
		let nullifier = sample_nullifier();
		crate::NullifierSet::<Test>::insert(nullifier, 1u64);

		let nullifiers: BoundedVec<Nullifier, ConstU32<2>> = vec![nullifier].try_into().unwrap();
		let commitments: BoundedVec<Commitment, ConstU32<2>> =
			vec![Commitment([3u8; 32])].try_into().unwrap();
		let proof: BoundedVec<u8, ConstU32<512>> = vec![1u8; 64].try_into().unwrap();

		// Should fail - nullifier already used
		let encrypted_memos: BoundedVec<_, ConstU32<2>> =
			vec![sample_encrypted_memo()].try_into().unwrap();

		assert_noop!(
			ShieldedPool::private_transfer(
				RuntimeOrigin::signed(1),
				proof,
				merkle_root,
				nullifiers,
				commitments,
				encrypted_memos,
			),
			Error::<Test>::NullifierAlreadyUsed
		);
	});
}
