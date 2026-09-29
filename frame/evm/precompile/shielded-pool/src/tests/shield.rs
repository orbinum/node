//! `shield`.

use super::*;

#[test]
fn shield_rejects_truncated_input() {
	new_test_ext().execute_with(|| {
		// Selector only: the head is missing.
		let mut h = MockHandle::new(crate::calls::shield::SELECTOR.to_vec());
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"shield: input too short",
		);
	});
}

#[test]
fn shield_accepts_smallest_non_zero_amount() {
	// There is no minimum shield amount: msg.value = 1 must go through.
	new_test_ext().execute_with(|| {
		let input = encode_shield(0, [0x11; 32], &[0xAB; 180]);
		let mut h = MockHandle::with_value(input, 1);
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn shield_stores_commitment_and_updates_balance() {
	new_test_ext().execute_with(|| {
		let commitment = [0x11; 32];
		let input = encode_shield(0, commitment, &[0xAB; 180]);
		let mut h = MockHandle::with_value(input, 1_000);
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

		assert_eq!(pallet_shielded_pool::MerkleTreeSize::<Test>::get(), 1);
		assert_eq!(
			pallet_shielded_pool::PoolBalancePerAsset::<Test>::get(0),
			1_000
		);
		let leaf = pallet_shielded_pool::MerkleLeaves::<Test>::get(0).unwrap();
		assert_eq!(leaf, pallet_shielded_pool::Commitment::from(commitment));
	});
}

#[test]
fn shield_multiple_commitments_are_all_stored() {
	new_test_ext().execute_with(|| {
		for (i, byte) in [0x11u8, 0x22, 0x33].iter().enumerate() {
			do_shield(canon(*byte), 500);
			assert_eq!(
				pallet_shielded_pool::MerkleTreeSize::<Test>::get(),
				(i + 1) as u32
			);
		}
		assert_eq!(
			pallet_shielded_pool::PoolBalancePerAsset::<Test>::get(0),
			1_500
		);
	});
}

#[test]
fn shield_updates_merkle_root_after_each_insertion() {
	new_test_ext().execute_with(|| {
		let root_before = current_root();
		do_shield(canon(0x42), 1_000);
		let root_after = current_root();
		assert_ne!(root_before, root_after, "root must change after shield");
	});
}

#[test]
fn shield_with_zero_value_rejected() {
	new_test_ext().execute_with(|| {
		let input = encode_shield(0, canon(0xAA), &[0x00; 180]);
		let mut h = MockHandle::with_value(input, 0);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}
