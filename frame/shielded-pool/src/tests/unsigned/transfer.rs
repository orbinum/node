// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Admission of `private_transfer`: the checks it runs before the pool takes it.

use super::*;

// ── validate_private_transfer ────────────────────────────────────────────────

#[test]
fn private_transfer_valid_transaction() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &0u128, 1);
		assert!(result.is_ok());
	});
}

#[test]
fn private_transfer_unknown_root_rejected() {
	new_test_ext().execute_with(|| {
		let result = validate_private_transfer(&[0xFFu8; 32], &nullifiers_of(&[0x01]), &0u128, 1);
		assert!(result.is_err());
	});
}

/// A dummy slot must repeat the real input's root: another known root (a sealed
/// tree's) or an unknown one is turned away before the proof is checked.
#[test]
fn private_transfer_dummy_root_that_differs_rejected() {
	use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
	new_test_ext().execute_with(|| {
		MerkleRepository::insert_sealed_root::<Test>(0, [0x5E; 32]);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		for dummy_root in [[0x5E; 32], [0xFF; 32]] {
			let mut req = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01]), 0, 3);
			req.merkle_roots[1] = dummy_root;
			assert_eq!(
				admit::validate_private_transfer(Some(&proof()), &req),
				Err(TransactionValidityError::Invalid(
					InvalidTransaction::Custom(codes::INVALID_SPEND)
				))
			);
		}
	});
}

/// Two real inputs from two trees: an unknown root in either slot gets the
/// unknown-root code.
#[test]
fn private_transfer_unknown_root_in_either_real_slot_rejected() {
	use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		for slot in 0..2 {
			let mut req = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01, 0x02]), 0, 3);
			req.merkle_roots[slot] = [0xFF; 32];
			assert_eq!(
				admit::validate_private_transfer(Some(&proof()), &req),
				Err(TransactionValidityError::Invalid(
					InvalidTransaction::Custom(codes::UNKNOWN_ROOT)
				))
			);
		}
	});
}

#[test]
fn private_transfer_nullifier_used_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let n = nullifier(0x05);
		NullifierRepository::mark_as_used::<Test>(n, 1u64);
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x05]), &0u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn private_transfer_two_nullifiers_one_used_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let used = nullifier(0x10);
		NullifierRepository::mark_as_used::<Test>(used, 1u64);
		// 0x10 is used, 0x11 is fresh — full list should still fail
		let result =
			validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x10, 0x11]), &0u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn private_transfer_with_fee_builds_valid_transaction() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let result = validate_private_transfer(
			&KNOWN_ROOT,
			&nullifiers_of(&[0xA1, 0xA2]),
			&100u128, // non-zero fee,
			1,
		);
		assert!(result.is_ok());
	});
}

#[test]
fn private_transfer_dummy_nullifier_zero_not_stale() {
	// A dummy input carries nullifier = [0u8; 32].
	// It must never be treated as "already used" even if [0u8;32] happened to
	// appear in the set (it cannot be inserted from mark_as_used, but this
	// confirms the skip logic).
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// [0u8;32] is the dummy sentinel — should be ignored by validation
		let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers.try_push(nullifier(0x01)).ok();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok(); // dummy
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers, &0u128, 1);
		assert!(
			result.is_ok(),
			"dummy nullifier should not cause Stale rejection"
		);
	});
}

#[test]
fn private_transfer_real_nullifier_still_checked_alongside_dummy() {
	// When the real nullifier (non-zero) is already used, the tx must be
	// rejected even if the second slot contains a dummy.
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let real = nullifier(0xBB);
		NullifierRepository::mark_as_used::<Test>(real, 1u64);
		let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers.try_push(real).ok();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok(); // dummy
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers, &0u128, 1);
		assert!(
			result.is_err(),
			"used real nullifier must still be rejected"
		);
	});
}

#[test]
fn private_transfer_all_dummy_nullifiers_rejected() {
	// Both nullifiers are [0u8;32] → no real input note → must be rejected
	// as anti-spam (Custom(2)) before entering the tx pool.
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok();
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers, &0u128, 1);
		assert!(result.is_err(), "all-dummy-nullifier tx must be rejected");
	});
}
