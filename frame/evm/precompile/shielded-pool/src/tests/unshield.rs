//! `unshield`.

use super::*;

#[test]
fn unshield_rejects_truncated_input() {
	new_test_ext().execute_with(|| {
		// The real selector, so the head-length check is what rejects it.
		let mut h = MockHandle::new(crate::calls::unshield::SELECTOR.to_vec());
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"unshield: input too short",
		);
	});
}

#[test]
fn unshield_selector_matches_signature() {
	// A hand-written selector that matches no signature is rejected as unknown,
	// so only this pins the accept path.
	let sig =
		b"unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)";
	let hash = sp_io::hashing::keccak_256(sig);
	assert_eq!(hash[..4], crate::calls::unshield::SELECTOR);
}

#[test]
fn unshield_rejects_empty_proof() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_unshield(
			&[],
			root,
			canon(0x77),
			0,
			100,
			recipient_bytes(),
			0,
			[0u8; 32],
			&[],
			1,
		);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn unshield_happy_path() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let nullifier = canon(0x77);

		let input = encode_unshield(
			&[0x09, 0x09],
			root,
			nullifier,
			0,
			100,
			recipient_bytes(),
			0,
			[0u8; 32],
			&[],
			1,
		);
		let mut h = MockHandle::new(input);
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

		// Pool balance decreases by the withdrawn amount.
		assert_eq!(
			pallet_shielded_pool::PoolBalancePerAsset::<Test>::get(0),
			4_900
		);
		// Nullifier is marked spent.
		assert!(pallet_shielded_pool::NullifierSet::<Test>::get(
			pallet_shielded_pool::Nullifier::from(nullifier)
		)
		.is_some());
	});
}

#[test]
fn unshield_rejects_double_spend() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let nullifier = canon(0x77);

		let input = encode_unshield(
			&[0x09, 0x09],
			root,
			nullifier,
			0,
			100,
			recipient_bytes(),
			0,
			[0u8; 32],
			&[],
			1,
		);
		let mut h = MockHandle::new(input.clone());
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

		let mut h2 = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h2));
	});
}

#[test]
fn unshield_full_balance() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 1_000);
		let root = current_root();
		let input = encode_unshield(
			&[0x01],
			root,
			canon(0x99),
			0,
			1_000,
			recipient_bytes(),
			0,
			[0u8; 32],
			&[],
			1,
		);
		let mut h = MockHandle::new(input);
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		assert_eq!(pallet_shielded_pool::PoolBalancePerAsset::<Test>::get(0), 0);
	});
}

#[test]
fn unshield_rejects_zero_recipient() {
	// AccountId32 of all zeros is a permanent burn address.  The precompile
	// must reject it before dispatching to avoid silent token destruction.
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_unshield(
			&[0x09, 0x09],
			root,
			canon(0x77),
			0,
			100,
			[0u8; 32], // zero AccountId32
			0,
			[0u8; 32],
			&[],
			1,
		);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn unshield_rejects_zero_amount() {
	// amount = 0 is semantically invalid and must be rejected at the precompile
	// level before dispatch.
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_unshield(
			&[0x09, 0x09],
			root,
			canon(0x77),
			0,
			0, // zero amount
			recipient_bytes(),
			0,
			[0u8; 32],
			&[],
			1,
		);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}
