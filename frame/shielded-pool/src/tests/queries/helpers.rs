// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! `Pallet` helpers: the pool account and the Merkle tree delegations.

use crate::{
	storage::MerkleRepository,
	tests::mock::{Test, acc, new_test_ext},
	types::Commitment,
};
use frame_support::assert_ok;

#[test]
fn pool_account_id_is_non_zero() {
	new_test_ext().execute_with(|| {
		let pool = crate::Pallet::<Test>::pool_account_id();
		assert_ne!(pool, acc(0));
	});
}

#[test]
fn pool_account_id_is_deterministic() {
	new_test_ext().execute_with(|| {
		let a = crate::Pallet::<Test>::pool_account_id();
		let b = crate::Pallet::<Test>::pool_account_id();
		assert_eq!(a, b);
	});
}

#[test]
fn insert_leaf_succeeds_and_returns_zero() {
	new_test_ext().execute_with(|| {
		let c = Commitment::new([0x01u8; 32]);
		let idx = crate::Pallet::<Test>::insert_leaf(c).unwrap();
		assert_eq!(idx, 0);
	});
}

#[test]
fn insert_leaf_sequential_indices() {
	new_test_ext().execute_with(|| {
		assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(
			[0x01u8; 32]
		)));
		let idx = crate::Pallet::<Test>::insert_leaf(Commitment::new([0x02u8; 32])).unwrap();
		assert_eq!(idx, 1);
	});
}

#[test]
fn get_merkle_path_none_for_empty_tree() {
	new_test_ext().execute_with(|| {
		assert!(crate::Pallet::<Test>::get_merkle_path(0).is_none());
	});
}

#[test]
fn get_merkle_path_some_after_insert() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::insert_leaf(Commitment::new([0x02u8; 32])).unwrap();
		assert!(crate::Pallet::<Test>::get_merkle_path(0).is_some());
	});
}

#[test]
fn get_merkle_path_none_out_of_bounds() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::insert_leaf(Commitment::new([0x03u8; 32])).unwrap();
		assert!(crate::Pallet::<Test>::get_merkle_path(99).is_none());
	});
}

#[test]
fn verify_merkle_proof_valid_after_insert() {
	new_test_ext().execute_with(|| {
		let leaf = [0x10u8; 32];
		crate::Pallet::<Test>::insert_leaf(Commitment::new(leaf)).unwrap();
		let root = MerkleRepository::get_poseidon_root::<Test>();
		let path = crate::Pallet::<Test>::get_merkle_path(0).unwrap();
		assert!(crate::Pallet::<Test>::verify_merkle_proof(
			&root, &leaf, &path
		));
	});
}

#[test]
fn verify_merkle_proof_fails_for_wrong_root() {
	new_test_ext().execute_with(|| {
		let leaf = [0x11u8; 32];
		crate::Pallet::<Test>::insert_leaf(Commitment::new(leaf)).unwrap();
		let path = crate::Pallet::<Test>::get_merkle_path(0).unwrap();
		assert!(!crate::Pallet::<Test>::verify_merkle_proof(
			&[0xFFu8; 32],
			&leaf,
			&path
		));
	});
}

#[test]
fn get_leaf_index_none_for_unknown_commitment() {
	new_test_ext().execute_with(|| {
		assert!(crate::Pallet::<Test>::get_leaf_index(&Commitment::new([0xFFu8; 32])).is_none());
	});
}

#[test]
fn get_leaf_index_returns_correct_index_after_insert() {
	new_test_ext().execute_with(|| {
		let c = Commitment::new([0x20u8; 32]);
		crate::Pallet::<Test>::insert_leaf(c).unwrap();
		assert_eq!(crate::Pallet::<Test>::get_leaf_index(&c), Some(0));
	});
}

#[test]
fn get_leaf_index_returns_correct_index_for_second_leaf() {
	new_test_ext().execute_with(|| {
		let c0 = Commitment::new([0x30u8; 32]);
		let c1 = Commitment::new([0x31u8; 32]);
		crate::Pallet::<Test>::insert_leaf(c0).unwrap();
		crate::Pallet::<Test>::insert_leaf(c1).unwrap();
		assert_eq!(crate::Pallet::<Test>::get_leaf_index(&c1), Some(1));
	});
}
