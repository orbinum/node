//! `privateTransfer`.

use super::*;

#[test]
fn private_transfer_rejects_truncated_input() {
	new_test_ext().execute_with(|| {
		// The real selector, taken from the decoder. A wrong literal here would
		// still make this test pass — a wrong selector is rejected as
		// "unknown selector" — while testing nothing about truncation.
		let mut h = MockHandle::new(crate::calls::private_transfer::SELECTOR.to_vec());
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn private_transfer_selector_matches_signature() {
	// The constant must be derived from the ABI signature — this is the guard
	// against a hand-written selector that never matches the code.
	let sig = b"privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)";
	let hash = sp_io::hashing::keccak_256(sig);
	assert_eq!(hash[..4], crate::calls::private_transfer::SELECTOR);
}

#[test]
fn private_transfer_rejects_empty_proof() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		// empty proof → MockZkVerifier returns Err
		let input = encode_private_transfer(
			&[],
			root,
			&[[0x11; 32], [0x22; 32]],
			&[canon(0x33), canon(0x44)],
			&[vec![0xAA; 180], vec![0xBB; 180]],
			0,
			0,
			1,
		);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn private_transfer_rejects_zero_nullifiers() {
	// Calling with an empty nullifier array must be rejected at the precompile
	// boundary before touching the pallet.
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_private_transfer(
			&[0x01],
			root,
			&[], // 0 nullifiers
			&[], // 0 commitments
			&[], // 0 memos
			0,
			0,
			1,
		);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn private_transfer_rejects_mismatched_nullifier_commitment_count() {
	// 2 nullifiers but 1 commitment — structurally inconsistent.
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_private_transfer(
			&[0x01],
			root,
			&[[0x11; 32], [0x22; 32]], // 2 nullifiers
			&[canon(0x33)],            // 1 commitment
			&[vec![0xAA; 180]],        // 1 memo
			0,
			0,
			1,
		);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn private_transfer_rejects_mismatched_commitment_memo_count() {
	// 2 commitments but 1 memo — structurally inconsistent.
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_private_transfer(
			&[0x01],
			root,
			&[[0x11; 32], [0x22; 32]],   // 2 nullifiers
			&[canon(0x33), canon(0x44)], // 2 commitments
			&[vec![0xAA; 180]],          // 1 memo — mismatch
			0,
			0,
			1,
		);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn private_transfer_happy_path() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let nullifier_1 = [0x11; 32];
		let nullifier_2 = [0x22; 32];
		let commitment_1 = canon(0x33);
		let commitment_2 = canon(0x44);

		let input = encode_private_transfer(
			&[0x01, 0x02, 0x03],
			root,
			&[nullifier_1, nullifier_2],
			&[commitment_1, commitment_2],
			&[vec![0xAA; 180], vec![0xBB; 180]],
			0,
			0,
			1,
		);
		let mut h = MockHandle::new(input);
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

		// Both input nullifiers must be spent.
		assert!(pallet_shielded_pool::NullifierSet::<Test>::get(
			pallet_shielded_pool::Nullifier::from(nullifier_1)
		)
		.is_some());
		assert!(pallet_shielded_pool::NullifierSet::<Test>::get(
			pallet_shielded_pool::Nullifier::from(nullifier_2)
		)
		.is_some());

		// Both output commitments must land in the tree (indices 1 and 2).
		assert_eq!(pallet_shielded_pool::MerkleTreeSize::<Test>::get(), 3);
		assert_eq!(
			pallet_shielded_pool::MerkleLeaves::<Test>::get(1).unwrap(),
			pallet_shielded_pool::Commitment::from(commitment_1)
		);
		assert_eq!(
			pallet_shielded_pool::MerkleLeaves::<Test>::get(2).unwrap(),
			pallet_shielded_pool::Commitment::from(commitment_2)
		);
	});
}

#[test]
fn private_transfer_rejects_double_spend() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let nullifier = canon(0xDE);

		let input = encode_private_transfer(
			&[0x01],
			root,
			&[nullifier, [0x02; 32]],
			&[[0x03; 32], [0x04; 32]],
			&[vec![0xAA; 180], vec![0xBB; 180]],
			0,
			0,
			1,
		);
		let mut h = MockHandle::new(input.clone());
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

		// Second call reuses the same nullifier — must fail.
		let mut h2 = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h2));
	});
}

#[test]
fn private_transfer_root_updates_after_outputs() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root_before = current_root();

		let input = encode_private_transfer(
			&[0x01],
			root_before,
			&[[0x11; 32], [0x22; 32]],
			&[canon(0x33), canon(0x44)],
			&[vec![0xAA; 180], vec![0xBB; 180]],
			0,
			0,
			1,
		);
		let mut h = MockHandle::new(input);
		assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

		assert_ne!(
			current_root(),
			root_before,
			"root must change after private_transfer"
		);
	});
}

#[test]
fn a_memo_longer_than_the_maximum_is_rejected_by_execute() {
	new_test_ext().execute_with(|| {
		let oversized = pallet_shielded_pool::types::MAX_ENCRYPTED_MEMO_SIZE as usize + 1;
		let input = encode_private_transfer(
			&[0x01, 0x02, 0x03],
			current_root(),
			&[[0x11; 32], [0x22; 32]],
			&[canon(0x33), canon(0x44)],
			&[vec![0xAA; oversized], vec![0xBB; 180]],
			0,
			0,
			1,
		);
		let mut h = MockHandle::new(input);
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"bytes[] item is too long",
		);
	});
}
