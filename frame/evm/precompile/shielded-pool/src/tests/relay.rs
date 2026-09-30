//! Relay commits and public fee claims.

use super::*;

/// A handle whose EVM caller is the mock's registered relay address.
fn from_relayer(input: Vec<u8>) -> MockHandle {
	let mut h = MockHandle::new(input);
	h.context.caller = registered_relayer();
	h
}

#[test]
fn relay_selectors_match_their_signatures() {
	use sp_io::hashing::keccak_256;
	assert_eq!(
		&keccak_256(b"commitRelay(bytes32[])")[..4],
		&crate::selectors::COMMIT_RELAY
	);
	assert_eq!(
		&keccak_256(b"claimRelayFees(uint32,uint256)")[..4],
		&crate::selectors::CLAIM_RELAY_FEES
	);
}

#[test]
fn registered_relayer_can_commit() {
	new_test_ext().execute_with(|| {
		let commits = [[0x11u8; 32], [0x22u8; 32]];
		let mut h = from_relayer(encode_commit_relay(&commits));
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		assert_eq!(
			recorded_commits(),
			commits
				.iter()
				.map(|c| sp_core::H256(*c))
				.collect::<Vec<_>>()
		);
	});
}

#[test]
fn unregistered_caller_cannot_commit() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(encode_commit_relay(&[[0x11u8; 32]]));
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		assert!(recorded_commits().is_empty());
	});
}

#[test]
fn commit_relay_rejects_empty_and_oversized_batches() {
	new_test_ext().execute_with(|| {
		let mut h = from_relayer(encode_commit_relay(&[]));
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"at least one",
		);

		let too_many =
			vec![[0x11u8; 32]; pallet_shielded_pool::MAX_RELAY_COMMITS_PER_CALL as usize + 1];
		let mut h = from_relayer(encode_commit_relay(&too_many));
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"too many items",
		);
	});
}

#[test]
fn registered_relayer_claims_into_its_mirror() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x41), 1_000);
		set_pending_relay_fees(300);

		let mut h = from_relayer(encode_claim_relay_fees(0, 200));
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

		assert_eq!(pending_relay_fees(), 100);
		let mirror = <crate::mock::MirrorAccount as sp_runtime::traits::Convert<_, _>>::convert(
			registered_relayer(),
		);
		assert_eq!(pallet_balances::Pallet::<Test>::free_balance(mirror), 200);
	});
}

#[test]
fn unregistered_caller_cannot_claim() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x42), 1_000);
		set_pending_relay_fees(300);
		let mut h = MockHandle::new(encode_claim_relay_fees(0, 100));
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		assert_eq!(pending_relay_fees(), 300);
	});
}

#[test]
fn claim_relay_fees_rejects_zero_and_short_input() {
	new_test_ext().execute_with(|| {
		let mut h = from_relayer(encode_claim_relay_fees(0, 0));
		expect_error_msg(ShieldedPoolPrecompile::<Test>::execute(&mut h), "non-zero");
		let mut short = encode_claim_relay_fees(0, 1);
		short.truncate(40);
		let mut h = from_relayer(short);
		expect_error_msg(ShieldedPoolPrecompile::<Test>::execute(&mut h), "too short");
	});
}

/// The relay commit a node derives from calldata identifies the same
/// spend the pallet credits when it executes that calldata.
#[test]
fn relayable_calldata_hashes_like_the_extrinsic() {
	let input = encode_unshield(
		&[0x01u8; 72],
		canon(0xBB),
		canon(1),
		0,
		500,
		recipient_bytes(),
		7,
		[0u8; 32],
		&[],
		1,
	);
	let call = crate::decode_relayable_call::<Test>(&input).expect("unshield decodes");
	let expected = pallet_shielded_pool::operations::unshield::UnshieldRequest::<Test> {
		merkle_root: canon(0xBB),
		nullifier: pallet_shielded_pool::Nullifier(canon(1)),
		asset_id: 0,
		amount: 500,
		recipient: crate::mock::caller_account(),
		fee: 7,
		change_commitment: [0u8; 32],
		change_memo: Default::default(),
		circuit_version: 1,
	}
	.op_hash()
	.unwrap();
	assert_eq!(
		pallet_shielded_pool::operations::fees::relay_op_hash(&call),
		Some(expected)
	);

	// Only spends are relayable.
	assert!(crate::decode_relayable_call::<Test>(&encode_claim_relay_fees(0, 1)).is_none());
	assert!(crate::decode_relayable_call::<Test>(&[0x4e]).is_none());
}

#[test]
fn relayable_transfer_calldata_hashes_like_the_extrinsic() {
	let memos = vec![vec![0x5A; 180]];
	let input = encode_private_transfer(
		&[0xAB; 128],
		canon(0xBB),
		&[canon(1)],
		&[canon(2)],
		&memos,
		0,
		7,
		2,
	);
	let call = crate::decode_relayable_call::<Test>(&input).expect("privateTransfer decodes");
	let expected = pallet_shielded_pool::operations::private_transfer::TransferRequest::<Test> {
		merkle_root: canon(0xBB),
		nullifiers: vec![pallet_shielded_pool::Nullifier(canon(1))]
			.try_into()
			.unwrap(),
		commitments: vec![pallet_shielded_pool::Commitment(canon(2))]
			.try_into()
			.unwrap(),
		memos: vec![pallet_shielded_pool::types::EncryptedMemo::from_bytes(&memos[0]).unwrap()]
			.try_into()
			.unwrap(),
		asset_id: 0,
		fee: 7,
		circuit_version: 2,
	}
	.op_hash();
	assert_eq!(
		pallet_shielded_pool::operations::fees::relay_op_hash(&call),
		Some(expected)
	);
}

#[test]
fn claim_relay_fees_rejects_an_amount_above_u128() {
	new_test_ext().execute_with(|| {
		let mut input = encode_claim_relay_fees(0, 0);
		input[4 + 32..4 + 48].copy_from_slice(&[0xFF; 16]); // high half of the amount word
		let mut h = from_relayer(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn commit_relay_rejects_an_offset_past_the_input() {
	new_test_ext().execute_with(|| {
		let mut input = encode_commit_relay(&[[0x11; 32]]);
		input[4..36].copy_from_slice(&u256_word(4096));
		let mut h = from_relayer(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		assert!(recorded_commits().is_empty());
	});
}

#[test]
fn delegated_calls_are_refused() {
	new_test_ext().execute_with(|| {
		let mut h = from_relayer(encode_commit_relay(&[[0x11; 32]]));
		h.code_address = sp_core::H160::repeat_byte(0x08); // DELEGATECALL: code ≠ context
		expect_error_msg(ShieldedPoolPrecompile::<Test>::execute(&mut h), "delegated");
		assert!(recorded_commits().is_empty());
	});
}

#[test]
fn static_calls_are_refused() {
	new_test_ext().execute_with(|| {
		let mut h = from_relayer(encode_claim_relay_fees(0, 1));
		h.is_static = true;
		expect_error_msg(ShieldedPoolPrecompile::<Test>::execute(&mut h), "static");
	});
}

/// A pallet error reverts (unused gas returned) with the reason as `Error(string)`.
#[test]
fn a_pallet_error_reverts_with_its_reason() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(encode_commit_relay(&[[0x11; 32]]));
		match ShieldedPoolPrecompile::<Test>::execute(&mut h) {
			Err(fp_evm::PrecompileFailure::Revert { output, .. }) => {
				assert_eq!(&output[..4], &[0x08, 0xc3, 0x79, 0xa0]);
				let reason_len = u64::from_be_bytes(output[60..68].try_into().unwrap()) as usize;
				assert!(
					reason_len > 0 && output.len() >= 68 + reason_len,
					"reason is carried"
				);
			}
			other => panic!("expected a revert, got {other:?}"),
		}
	});
}

#[test]
fn claim_relay_fees_above_pending_reverts_and_moves_nothing() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x43), 1_000);
		set_pending_relay_fees(100);
		let mut h = from_relayer(encode_claim_relay_fees(0, 101));
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));

		assert_eq!(pending_relay_fees(), 100);
		let mirror = <crate::mock::MirrorAccount as sp_runtime::traits::Convert<_, _>>::convert(
			registered_relayer(),
		);
		assert_eq!(pallet_balances::Pallet::<Test>::free_balance(mirror), 0);
	});
}

#[test]
fn claim_relay_fees_rejects_an_asset_id_above_u32() {
	new_test_ext().execute_with(|| {
		set_pending_relay_fees(100);
		let mut input = encode_claim_relay_fees(0, 1);
		input[4 + 27] = 0x01; // the byte above the uint32 in the asset_id word
		let mut h = from_relayer(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		assert_eq!(pending_relay_fees(), 100);
	});
}

#[test]
fn a_delegated_shield_is_refused() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::with_value(encode_shield(0, canon(0x44), &[0x5A; 180]), 1_000);
		h.code_address = sp_core::H160::repeat_byte(0x08); // DELEGATECALL: code ≠ context
		expect_error_msg(ShieldedPoolPrecompile::<Test>::execute(&mut h), "delegated");
	});
}

/// Only `shield` is payable. The executor moves `msg.value` to the precompile
/// before this code runs, and nothing would send it back out, so every other
/// call refuses it rather than stranding the caller's funds at the address.
#[test]
fn the_non_payable_calls_refuse_msg_value() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x51), 1_000);
		set_pending_relay_fees(300);
		let root = current_root();
		let calls: Vec<(&str, Vec<u8>)> = vec![
			("commitRelay", encode_commit_relay(&[[0x11; 32]])),
			("claimRelayFees", encode_claim_relay_fees(0, 100)),
			(
				"unshield",
				encode_unshield(
					&[0x01u8; 72],
					root,
					canon(1),
					0,
					500,
					recipient_bytes(),
					0,
					[0u8; 32],
					&[],
					1,
				),
			),
			(
				"privateTransfer",
				encode_private_transfer(
					&[0x01, 0x02, 0x03],
					root,
					&[[0x11; 32], [0x22; 32]],
					&[canon(0x33), canon(0x44)],
					&[vec![0xAA; 180], vec![0xBB; 180]],
					0,
					0,
					1,
				),
			),
		];
		for (name, input) in calls {
			let mut h = MockHandle::with_value(input, 1_000);
			h.context.caller = registered_relayer();
			expect_error_msg(
				ShieldedPoolPrecompile::<Test>::execute(&mut h),
				"not payable",
			);
			assert_eq!(pending_relay_fees(), 300, "{name} moved a pending fee");
		}
	});
}

#[test]
fn truncated_spend_calldata_is_not_relayable() {
	let unshield = encode_unshield(
		&[0x01u8; 72],
		canon(0xBB),
		canon(1),
		0,
		500,
		recipient_bytes(),
		7,
		[0u8; 32],
		&[],
		1,
	);
	let transfer = encode_private_transfer(
		&[0xAB; 128],
		canon(0xBB),
		&[canon(1), [0u8; 32]],
		&[canon(2), canon(3)],
		&[vec![0x5A; 180], vec![0x5B; 180]],
		0,
		7,
		2,
	);
	for input in [unshield, transfer] {
		assert!(crate::decode_relayable_call::<Test>(&input).is_some());
		// Cut inside the head, and inside the last tail's data (not just its padding).
		for len in [4 + 64, input.len() - 32] {
			assert!(
				crate::decode_relayable_call::<Test>(&input[..len]).is_none(),
				"selector {:02x?} decoded at {len}/{}",
				&input[..4],
				input.len()
			);
		}
	}
}
