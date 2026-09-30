//! Multi-step flows through the precompile.

use super::*;

#[test]
fn full_lifecycle_shield_transfer_unshield() {
	new_test_ext().execute_with(|| {
		// 1. Shield
		do_shield(canon(0xAA), 10_000);
		assert_eq!(pallet_shielded_pool::MerkleTreeSize::<Test>::get(), 1);

		// 2. Private transfer
		let root_1 = current_root();
		let nullifier_in = canon(0xBB);
		let commitment_out_1 = canon(0xCC);
		let commitment_out_2 = canon(0xDD);

		let pt_input = encode_private_transfer(
			&[0x01],
			root_1,
			&[nullifier_in, [0x00; 32]],
			&[commitment_out_1, commitment_out_2],
			&[vec![0xAA; 180], vec![0xBB; 180]],
			0,
			0,
			1,
		);
		let mut h_pt = MockHandle::new(pt_input);
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h_pt));
		assert_eq!(pallet_shielded_pool::MerkleTreeSize::<Test>::get(), 3);

		// 3. Unshield one of the outputs
		let root_2 = current_root();
		let nullifier_out = canon(0xEE);
		let unshield_input = encode_unshield(
			&[0x02],
			root_2,
			nullifier_out,
			0,
			500,
			recipient_bytes(),
			0,
			[0u8; 32],
			&[],
			1,
		);
		let mut h_us = MockHandle::new(unshield_input);
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h_us));

		assert_eq!(
			pallet_shielded_pool::PoolBalancePerAsset::<Test>::get(0),
			9_500
		);
	});
}
