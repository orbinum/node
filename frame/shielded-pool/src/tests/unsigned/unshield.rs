// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Admission of `unshield`.

use super::*;

// ── validate_unshield ────────────────────────────────────────────────────────

#[test]
fn unshield_valid_transaction() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x10), &0u32, &500u128, &0u128, 1);
		assert!(result.is_ok());
	});
}

#[test]
fn unshield_unknown_root_rejected() {
	new_test_ext().execute_with(|| {
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let result = validate_unshield(&[0xEEu8; 32], &nullifier(0x10), &0u32, &500u128, &0u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn unshield_nullifier_used_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let n = nullifier(0x20);
		NullifierRepository::mark_as_used::<Test>(n, 1u64);
		let result = validate_unshield(&KNOWN_ROOT, &n, &0u32, &500u128, &0u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn unshield_insufficient_pool_balance_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 50u128); // only 50
		let result = validate_unshield(
			&KNOWN_ROOT,
			&nullifier(0x30),
			&0u32,
			&100u128, // 100 > 50
			&0u128,
			1,
		);
		assert!(result.is_err());
	});
}

#[test]
fn unshield_amount_plus_fee_checked_against_pool_balance() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// pool has 150; amount=100 + fee=60 = 160 > 150 → reject
		PoolBalanceRepository::set_asset_balance::<Test>(0, 150u128);
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x40), &0u32, &100u128, &60u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn unshield_exact_pool_balance_accepted() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// amount=100 + fee=50 = 150 == pool → accept
		PoolBalanceRepository::set_asset_balance::<Test>(0, 150u128);
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x50), &0u32, &100u128, &50u128, 1);
		assert!(result.is_ok());
	});
}
