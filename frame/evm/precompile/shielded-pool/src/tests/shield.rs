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

/// The pre-proof ABI (`asset_id, commitment, memo`) is three slots: too short now,
/// so an outdated client fails loudly instead of shielding without a proof.
#[test]
fn shield_rejects_the_old_three_slot_head() {
	new_test_ext().execute_with(|| {
		let mut input = crate::calls::shield::SELECTOR.to_vec();
		input.extend_from_slice(&[0u8; 96]);
		let mut h = MockHandle::with_value(input, 1_000);
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"shield: input too short",
		);
	});
}

#[test]
fn shield_rejects_an_empty_proof() {
	new_test_ext().execute_with(|| {
		let input = encode_shield_with(0, canon(0x12), &[0xAB; 180], &[], 1);
		let mut h = MockHandle::with_value(input, 1_000);
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"shield: proof must be non-empty",
		);
		assert_eq!(pallet_shielded_pool::MerkleTreeSize::<Test>::get(), 0);
	});
}

/// The amount reaches the pallet from `msg.value`, and the proof and version
/// from the calldata, unchanged.
#[test]
fn shield_decodes_proof_and_version_into_the_call() {
	new_test_ext().execute_with(|| {
		let proof = [0x5Au8; 96];
		let input = encode_shield_with(3, canon(0x13), &[0xAB; 180], &proof, 7);
		let h = MockHandle::with_value(input.clone(), 1_000);
		let call = crate::calls::shield::decode::<Test>(&h, &input)
			.ok()
			.unwrap();
		match call {
			pallet_shielded_pool::Call::shield {
				asset_id,
				amount,
				commitment,
				proof: decoded,
				circuit_version,
				..
			} => {
				assert_eq!(asset_id, 3);
				assert_eq!(amount, 1_000);
				assert_eq!(
					commitment,
					pallet_shielded_pool::Commitment::from(canon(0x13))
				);
				assert_eq!(decoded.into_inner(), proof.to_vec());
				assert_eq!(circuit_version, 7);
			}
			other => panic!("decoded to {other:?}"),
		}
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
