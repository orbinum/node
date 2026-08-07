// ─────────────────────────────────────────────────────────────────────────────
// Test helpers and ABI encoders
// ─────────────────────────────────────────────────────────────────────────────

use fp_evm::{ExitError, Precompile, PrecompileFailure};
use sp_core::U256;

use crate::{
	mock::{new_test_ext, MockHandle, Test},
	ShieldedPoolPrecompile,
};

// ─── Assertion helpers ───────────────────────────────────────────────────────

fn expect_error(result: Result<fp_evm::PrecompileOutput, PrecompileFailure>) {
	assert!(
		matches!(
			result,
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(_)
			})
		),
		"expected PrecompileFailure::Error(ExitError::Other(_)), got: {result:?}"
	);
}

fn assert_success(result: Result<fp_evm::PrecompileOutput, PrecompileFailure>) {
	match result {
		Ok(out) => assert_eq!(out.exit_status, fp_evm::ExitSucceed::Stopped),
		Err(e) => panic!("expected successful dispatch, got error: {e:?}"),
	}
}

/// Wraps an `Ok(())` into a fake `PrecompileOutput` so `expect_error` can accept
/// results from abi helpers that return `Result<T, PrecompileFailure>`.
fn lift<T>(r: Result<T, PrecompileFailure>) -> Result<fp_evm::PrecompileOutput, PrecompileFailure> {
	r.map(|_| fp_evm::PrecompileOutput {
		exit_status: fp_evm::ExitSucceed::Stopped,
		output: vec![],
	})
}

// ─── Low-level ABI encoding ──────────────────────────────────────────────────

fn u256_word(value: usize) -> [u8; 32] {
	U256::from(value).to_big_endian()
}

fn u256_word_u128(value: u128) -> [u8; 32] {
	U256::from(value).to_big_endian()
}

/// Encodes a single `bytes` value: `uint256(length) ++ data ++ zero-padding`.
fn encode_bytes(data: &[u8]) -> Vec<u8> {
	let padded = (data.len() + 31) & !31;
	let mut out = vec![0u8; 32 + padded];
	out[..32].copy_from_slice(&u256_word(data.len()));
	out[32..32 + data.len()].copy_from_slice(data);
	out
}

/// Encodes a `bytes32[]`: `uint256(count) ++ items`.
fn encode_bytes32_array(items: &[[u8; 32]]) -> Vec<u8> {
	let mut out = vec![0u8; 32 + items.len() * 32];
	out[..32].copy_from_slice(&u256_word(items.len()));
	for (i, item) in items.iter().enumerate() {
		out[32 + i * 32..64 + i * 32].copy_from_slice(item);
	}
	out
}

/// Encodes a `bytes[]` using head/tail ABI layout.
fn encode_bytes_array(items: &[Vec<u8>]) -> Vec<u8> {
	let count = items.len();
	let mut heads = vec![0u8; count * 32];
	let mut tails = Vec::new();
	let mut cursor = count * 32;

	for (i, item) in items.iter().enumerate() {
		heads[i * 32..(i + 1) * 32].copy_from_slice(&u256_word(cursor));
		let enc = encode_bytes(item);
		cursor += enc.len();
		tails.extend_from_slice(&enc);
	}

	let mut out = Vec::with_capacity(32 + heads.len() + tails.len());
	out.extend_from_slice(&u256_word(count));
	out.extend_from_slice(&heads);
	out.extend_from_slice(&tails);
	out
}

// ─── Call encoders ───────────────────────────────────────────────────────────

/// `shield(uint32 asset_id, bytes32 commitment, bytes encrypted_memo)`  selector `0x9feb22ea`
fn encode_shield(asset_id: u32, commitment: [u8; 32], memo: &[u8]) -> Vec<u8> {
	let mut input = vec![0x9f, 0xeb, 0x22, 0xea];
	let mut head = vec![0u8; 96];
	head[28..32].copy_from_slice(&asset_id.to_be_bytes());
	head[32..64].copy_from_slice(&commitment);
	head[64..96].copy_from_slice(&u256_word(96));
	input.extend_from_slice(&head);
	input.extend_from_slice(&encode_bytes(memo));
	input
}

/// `privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256)`  selector `0x8c0f5d24`
#[allow(clippy::too_many_arguments)]
fn encode_private_transfer(
	proof: &[u8],
	merkle_root: [u8; 32],
	nullifiers: &[[u8; 32]],
	commitments: &[[u8; 32]],
	memos: &[Vec<u8>],
	asset_id: u32,
	fee: u128,
	circuit_version: u32,
) -> Vec<u8> {
	let proof_enc = encode_bytes(proof);
	let nullifiers_enc = encode_bytes32_array(nullifiers);
	let commitments_enc = encode_bytes32_array(commitments);
	let memos_enc = encode_bytes_array(memos);

	// head: 8 slots × 32 = 256 bytes (added trailing uint32 circuitVersion)
	let head_size = 256usize;
	let off_proof = head_size;
	let off_nullifiers = off_proof + proof_enc.len();
	let off_commitments = off_nullifiers + nullifiers_enc.len();
	let off_memos = off_commitments + commitments_enc.len();

	let mut input = vec![0x66, 0xed, 0x2c, 0xd4];
	let mut head = vec![0u8; head_size];
	head[0..32].copy_from_slice(&u256_word(off_proof));
	head[32..64].copy_from_slice(&merkle_root);
	head[64..96].copy_from_slice(&u256_word(off_nullifiers));
	head[96..128].copy_from_slice(&u256_word(off_commitments));
	head[128..160].copy_from_slice(&u256_word(off_memos));
	head[188..192].copy_from_slice(&asset_id.to_be_bytes());
	head[192..224].copy_from_slice(&u256_word_u128(fee));
	head[252..256].copy_from_slice(&circuit_version.to_be_bytes());

	input.extend_from_slice(&head);
	input.extend_from_slice(&proof_enc);
	input.extend_from_slice(&nullifiers_enc);
	input.extend_from_slice(&commitments_enc);
	input.extend_from_slice(&memos_enc);
	input
}

/// `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)` selector `0x4e505348`
#[allow(clippy::too_many_arguments)]
fn encode_unshield(
	proof: &[u8],
	merkle_root: [u8; 32],
	nullifier: [u8; 32],
	asset_id: u32,
	amount: u128,
	recipient: [u8; 32],
	fee: u128,
	change_commitment: [u8; 32],
	change_encrypted_memo: &[u8],
	circuit_version: u32,
) -> Vec<u8> {
	// head: 10 slots × 32 = 320 bytes (added trailing uint32 circuitVersion);
	// tails (proof, memo) appended after.
	let mut input = vec![0x4e, 0x50, 0x53, 0x48];
	let mut head = vec![0u8; 320];
	let proof_offset = 320usize;
	let memo_offset = proof_offset + encode_bytes(proof).len();

	head[0..32].copy_from_slice(&u256_word(proof_offset));
	head[32..64].copy_from_slice(&merkle_root);
	head[64..96].copy_from_slice(&nullifier);
	head[124..128].copy_from_slice(&asset_id.to_be_bytes());
	head[128..160].copy_from_slice(&u256_word_u128(amount));
	head[160..192].copy_from_slice(&recipient);
	head[192..224].copy_from_slice(&u256_word_u128(fee));
	head[224..256].copy_from_slice(&change_commitment);
	head[256..288].copy_from_slice(&u256_word(memo_offset));
	head[316..320].copy_from_slice(&circuit_version.to_be_bytes());
	input.extend_from_slice(&head);
	input.extend_from_slice(&encode_bytes(proof));
	input.extend_from_slice(&encode_bytes(change_encrypted_memo));
	input
}

// ─── Convenience: shield then return the current Merkle root ─────────────────

fn do_shield(commitment: [u8; 32], value: u128) {
	let input = encode_shield(0, commitment, &[0xAB; 180]);
	let mut h = MockHandle::with_value(input, value);
	assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));
}

fn current_root() -> [u8; 32] {
	pallet_shielded_pool::Pallet::<Test>::poseidon_root()
}

fn recipient_bytes() -> [u8; 32] {
	let mut r = [0u8; 32];
	r.copy_from_slice(crate::mock::caller_account().as_ref());
	r
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: ABI router
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn router_rejects_empty_input() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(vec![]);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn router_rejects_3_byte_selector() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(vec![0x9f, 0xeb, 0x22]);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn router_rejects_unknown_selector() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(vec![0xff, 0xff, 0xff, 0xff]);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: ABI decoders (unit tests — no pallet state)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn abi_decode_u32_max_value() {
	let mut slot = [0u8; 32];
	slot[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
	assert_eq!(crate::abi::decode_u32(&slot).unwrap(), u32::MAX);
}

#[test]
fn abi_decode_u32_zero() {
	assert_eq!(crate::abi::decode_u32(&[0u8; 32]).unwrap(), 0u32);
}

#[test]
fn abi_decode_u32_rejects_short_slot() {
	expect_error(lift(crate::abi::decode_u32(&[0u8; 31])));
}

#[test]
fn abi_read_bytes32_copies_all_bytes() {
	let mut params = [0u8; 64];
	for i in 0..32 {
		params[32 + i] = i as u8;
	}
	let out = crate::abi::read_bytes32(&params, 32).unwrap();
	for i in 0..32u8 {
		assert_eq!(out[i as usize], i);
	}
}

#[test]
fn abi_read_bytes32_rejects_out_of_bounds() {
	expect_error(lift(crate::abi::read_bytes32(&[0u8; 31], 0)));
}

#[test]
fn abi_decode_bytes_at_slot_works() {
	let mut params = vec![0u8; 128];
	params[31] = 32; // offset pointer
	params[63] = 3; // length
	params[64..67].copy_from_slice(b"abc");
	assert_eq!(
		crate::abi::decode_bytes_at_slot(&params, 0).unwrap(),
		b"abc"
	);
}

#[test]
fn abi_decode_bytes_at_slot_rejects_invalid_offset() {
	let mut params = vec![0u8; 64];
	params[31] = 200; // offset beyond params
	expect_error(lift(crate::abi::decode_bytes_at_slot(&params, 0)));
}

#[test]
fn abi_decode_bytes_at_slot_rejects_truncated_data() {
	// offset=32, length=100, but only 32 bytes of data follow
	let mut params = vec![0u8; 96];
	params[31] = 32;
	params[63] = 100;
	expect_error(lift(crate::abi::decode_bytes_at_slot(&params, 0)));
}

#[test]
fn abi_decode_bytes_at_slot_empty_payload() {
	// length=0 is valid
	let mut params = vec![0u8; 64];
	params[31] = 32; // offset
				  // length word is 0 (already zeroed)
	assert_eq!(crate::abi::decode_bytes_at_slot(&params, 0).unwrap(), b"");
}

#[test]
fn abi_decode_bytes32_array_works() {
	let mut params = vec![0u8; 160];
	params[31] = 32; // offset
	params[63] = 2; // count
	params[64..96].copy_from_slice(&[0xAAu8; 32]);
	params[96..128].copy_from_slice(&[0xBBu8; 32]);
	let out = crate::abi::decode_bytes32_array_at_slot(&params, 0).unwrap();
	assert_eq!(out.len(), 2);
	assert_eq!(out[0], [0xAAu8; 32]);
	assert_eq!(out[1], [0xBBu8; 32]);
}

#[test]
fn abi_decode_bytes32_array_empty() {
	let mut params = vec![0u8; 64];
	params[31] = 32; // offset
				  // count = 0
	let out = crate::abi::decode_bytes32_array_at_slot(&params, 0).unwrap();
	assert!(out.is_empty());
}

#[test]
fn abi_decode_bytes32_array_rejects_truncated() {
	let mut params = vec![0u8; 96];
	params[31] = 32;
	params[63] = 3; // asks for 3×32=96 bytes but only 32 available
	expect_error(lift(crate::abi::decode_bytes32_array_at_slot(&params, 0)));
}

#[test]
fn abi_decode_bytes_array_works() {
	let mut params = vec![0u8; 288];
	params[31] = 32; // outer offset
	params[63] = 2; // count
	params[95] = 64; // rel offset element 0
	params[127] = 128; // rel offset element 1
					// element 0: len=1, data=0xAA
	params[159] = 1;
	params[160] = 0xAA;
	// element 1: len=2, data=0xBB 0xCC
	params[223] = 2;
	params[224] = 0xBB;
	params[225] = 0xCC;
	let out = crate::abi::decode_bytes_array_at_slot(&params, 0).unwrap();
	assert_eq!(out, vec![vec![0xAAu8], vec![0xBBu8, 0xCC]]);
}

#[test]
fn abi_decode_bytes_array_rejects_invalid_rel_offset() {
	let mut params = vec![0u8; 96];
	params[31] = 32;
	params[63] = 1;
	params[95] = 200; // rel offset way out of bounds
	expect_error(lift(crate::abi::decode_bytes_array_at_slot(&params, 0)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: shield
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn shield_rejects_truncated_input() {
	new_test_ext().execute_with(|| {
		// selector only — params missing
		let mut h = MockHandle::new(vec![0x9f, 0xeb, 0x22, 0xea]);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
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
			do_shield([*byte; 32], 500);
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
		do_shield([0x42; 32], 1_000);
		let root_after = current_root();
		assert_ne!(root_before, root_after, "root must change after shield");
	});
}

#[test]
fn shield_with_zero_value_rejected() {
	new_test_ext().execute_with(|| {
		let input = encode_shield(0, [0xAA; 32], &[0x00; 180]);
		let mut h = MockHandle::with_value(input, 0);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: private_transfer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn private_transfer_rejects_truncated_input() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(vec![0x8c, 0x0f, 0x5d, 0x24]);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn private_transfer_rejects_empty_proof() {
	new_test_ext().execute_with(|| {
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		// empty proof → MockZkVerifier returns Err
		let input = encode_private_transfer(
			&[],
			root,
			&[[0x11; 32], [0x22; 32]],
			&[[0x33; 32], [0x44; 32]],
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
		do_shield([0x55; 32], 5_000);
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
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let input = encode_private_transfer(
			&[0x01],
			root,
			&[[0x11; 32], [0x22; 32]], // 2 nullifiers
			&[[0x33; 32]],             // 1 commitment
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
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let input = encode_private_transfer(
			&[0x01],
			root,
			&[[0x11; 32], [0x22; 32]], // 2 nullifiers
			&[[0x33; 32], [0x44; 32]], // 2 commitments
			&[vec![0xAA; 180]],        // 1 memo — mismatch
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
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let nullifier_1 = [0x11; 32];
		let nullifier_2 = [0x22; 32];
		let commitment_1 = [0x33; 32];
		let commitment_2 = [0x44; 32];

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
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let nullifier = [0xDE; 32];

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
		do_shield([0x55; 32], 5_000);
		let root_before = current_root();

		let input = encode_private_transfer(
			&[0x01],
			root_before,
			&[[0x11; 32], [0x22; 32]],
			&[[0x33; 32], [0x44; 32]],
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests: unshield
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unshield_rejects_truncated_input() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(vec![0xcc, 0x1a, 0x3b, 0x38]);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn unshield_rejects_empty_proof() {
	new_test_ext().execute_with(|| {
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let input = encode_unshield(
			&[],
			root,
			[0x77; 32],
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
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let nullifier = [0x77; 32];

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
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let nullifier = [0x77; 32];

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
		do_shield([0x55; 32], 1_000);
		let root = current_root();
		let input = encode_unshield(
			&[0x01],
			root,
			[0x99; 32],
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
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let input = encode_unshield(
			&[0x09, 0x09],
			root,
			[0x77; 32],
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
		do_shield([0x55; 32], 5_000);
		let root = current_root();
		let input = encode_unshield(
			&[0x09, 0x09],
			root,
			[0x77; 32],
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests: multi-step flows
// ─────────────────────────────────────────────────────────────────────────────

/// Shield → private_transfer → unshield in one test to exercise the full lifecycle.
#[test]
fn full_lifecycle_shield_transfer_unshield() {
	new_test_ext().execute_with(|| {
		// 1. Shield
		do_shield([0xAA; 32], 10_000);
		assert_eq!(pallet_shielded_pool::MerkleTreeSize::<Test>::get(), 1);

		// 2. Private transfer
		let root_1 = current_root();
		let nullifier_in = [0xBB; 32];
		let commitment_out_1 = [0xCC; 32];
		let commitment_out_2 = [0xDD; 32];

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
		let nullifier_out = [0xEE; 32];
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

/// Ensures state is independent across multiple shield operations with different asset_id slots.
/// The mock only has asset 0 registered so multiple asset_ids will result in dispatch errors,
/// but the ABI decoding of asset_id must always round-trip correctly.
#[test]
fn shield_asset_id_round_trips_through_abi() {
	// We test ABI encoding/decoding in isolation via the abi module.
	for &id in &[0u32, 1, 42, u32::MAX] {
		let mut slot = [0u8; 32];
		slot[28..32].copy_from_slice(&id.to_be_bytes());
		assert_eq!(
			crate::abi::decode_u32(&slot).unwrap(),
			id,
			"asset_id {id} must round-trip"
		);
	}
}
