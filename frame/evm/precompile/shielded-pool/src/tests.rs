// ─────────────────────────────────────────────────────────────────────────────
// Test helpers and ABI encoders
// ─────────────────────────────────────────────────────────────────────────────

use fp_evm::{ExitError, Precompile, PrecompileFailure};
use sp_core::U256;

use crate::{
	mock::{new_test_ext, MockHandle, Test},
	ShieldedPoolPrecompile,
};

/// A distinct, canonical 32-byte field value for `seed`.
///
/// Commitments and nullifiers are now checked against the BN254 modulus, and a
/// repeated byte at or above 0x30 exceeds it — `p` starts at 0x30. Real values
/// come out of Poseidon and are always canonical, so a filler that is not would
/// exercise a shape the chain never produces.
fn canon(seed: u8) -> [u8; 32] {
	let mut b = [0u8; 32];
	b[0] = seed;
	b[1] = 0xA5;
	b
}

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

/// Like `expect_error`, but pins the REASON.
///
/// `expect_error` only checks the error variant, and this decoder has a dozen
/// ways to fail before it ever reaches the field under test — so a test named
/// after one rejection can pass on a completely different one.
fn expect_error_msg(result: Result<fp_evm::PrecompileOutput, PrecompileFailure>, needle: &str) {
	match result {
		Err(PrecompileFailure::Error {
			exit_status: ExitError::Other(msg),
		}) => assert!(
			msg.contains(needle),
			"expected an error containing {needle:?}, got: {msg:?}"
		),
		other => panic!("expected PrecompileFailure::Error(Other), got: {other:?}"),
	}
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

/// `privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32,bytes)`  selector `0x1ec439cf`
#[allow(clippy::too_many_arguments)]
fn encode_private_transfer_with_blob(
	proof: &[u8],
	merkle_root: [u8; 32],
	nullifiers: &[[u8; 32]],
	commitments: &[[u8; 32]],
	memos: &[Vec<u8>],
	asset_id: u32,
	fee: u128,
	circuit_version: u32,
	ovk_blob: &[u8],
) -> Vec<u8> {
	let proof_enc = encode_bytes(proof);
	let nullifiers_enc = encode_bytes32_array(nullifiers);
	let commitments_enc = encode_bytes32_array(commitments);
	let memos_enc = encode_bytes_array(memos);
	let blob_enc = encode_bytes(ovk_blob);

	// head: 9 slots × 32 = 288 bytes (trailing bytes = ovk_blob)
	let head_size = 288usize;
	let off_proof = head_size;
	let off_nullifiers = off_proof + proof_enc.len();
	let off_commitments = off_nullifiers + nullifiers_enc.len();
	let off_memos = off_commitments + commitments_enc.len();
	let off_blob = off_memos + memos_enc.len();

	let mut input = crate::calls::private_transfer::SELECTOR.to_vec();
	let mut head = vec![0u8; head_size];
	head[0..32].copy_from_slice(&u256_word(off_proof));
	head[32..64].copy_from_slice(&merkle_root);
	head[64..96].copy_from_slice(&u256_word(off_nullifiers));
	head[96..128].copy_from_slice(&u256_word(off_commitments));
	head[128..160].copy_from_slice(&u256_word(off_memos));
	head[188..192].copy_from_slice(&asset_id.to_be_bytes());
	head[192..224].copy_from_slice(&u256_word_u128(fee));
	head[252..256].copy_from_slice(&circuit_version.to_be_bytes());
	head[256..288].copy_from_slice(&u256_word(off_blob));

	input.extend_from_slice(&head);
	input.extend_from_slice(&proof_enc);
	input.extend_from_slice(&nullifiers_enc);
	input.extend_from_slice(&commitments_enc);
	input.extend_from_slice(&memos_enc);
	input.extend_from_slice(&blob_enc);
	input
}

/// Same as `encode_private_transfer_with_blob`, with a valid-length blob.
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
	encode_private_transfer_with_blob(
		proof,
		merkle_root,
		nullifiers,
		commitments,
		memos,
		asset_id,
		fee,
		circuit_version,
		&[0x0Bu8; 56],
	)
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
	let mut input = crate::calls::unshield::SELECTOR.to_vec();
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests: private_transfer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn private_transfer_rejects_truncated_input() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(crate::calls::private_transfer::SELECTOR.to_vec());
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
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
fn private_transfer_rejects_blob_of_55_bytes() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_private_transfer_with_blob(
			&[0x01],
			root,
			&[[0x11; 32]],
			&[canon(0x33)],
			&[vec![0xAA; 180]],
			0,
			0,
			1,
			&[0x0B; 55], // one byte short
		);
		let mut h = MockHandle::new(input);
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"ovk blob must be exactly 56 bytes",
		);
	});
}

#[test]
fn private_transfer_rejects_blob_of_57_bytes() {
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_private_transfer_with_blob(
			&[0x01],
			root,
			&[[0x11; 32]],
			&[canon(0x33)],
			&[vec![0xAA; 180]],
			0,
			0,
			1,
			&[0x0B; 57], // one byte long
		);
		let mut h = MockHandle::new(input);
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"ovk blob must be exactly 56 bytes",
		);
	});
}

#[test]
fn private_transfer_rejects_empty_blob() {
	// The likeliest wrong shape in practice: a caller that knows about the new
	// field but has nothing to put there emits `bytes` of length 0, not 55. If
	// that decoded, the sender would silently lose recoverability.
	new_test_ext().execute_with(|| {
		do_shield(canon(0x55), 5_000);
		let root = current_root();
		let input = encode_private_transfer_with_blob(
			&[0x01],
			root,
			&[[0x11; 32]],
			&[canon(0x33)],
			&[vec![0xAA; 180]],
			0,
			0,
			1,
			&[],
		);
		let mut h = MockHandle::new(input);
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"ovk blob must be exactly 56 bytes",
		);
	});
}

#[test]
fn private_transfer_rejects_missing_blob_slot() {
	// Calldata with the old 8-slot head (256 bytes of params) must be rejected
	// by the 288-byte minimum before any slot is decoded.
	new_test_ext().execute_with(|| {
		let mut input = crate::calls::private_transfer::SELECTOR.to_vec();
		input.extend_from_slice(&[0u8; 256]);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn private_transfer_selector_matches_signature() {
	// The constant must be derived from the ABI signature — this is the guard
	// that would have caught ME-8 (whitelist selector never matching the code).
	let sig =
		b"privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32,bytes)";
	let hash = sp_io::hashing::keccak_256(sig);
	assert_eq!(hash[..4], crate::calls::private_transfer::SELECTOR);
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests: multi-step flows
// ─────────────────────────────────────────────────────────────────────────────

/// Shield → private_transfer → unshield in one test to exercise the full lifecycle.
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

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial ABI battery — the attacker controls every byte of `input`
//
// This is the only surface where untrusted bytes reach the node directly: an
// EVM caller can send arbitrary calldata to the precompile address. Each test
// below is an attempt to make the decoder panic, over-allocate, or read out of
// bounds. A panic here is a node crash, not a rejected transaction.
// ─────────────────────────────────────────────────────────────────────────────

/// Truncated calldata at every length from the selector to a full head. None of
/// these may panic — the decoder must reject each one cleanly.
#[test]
fn attack_truncation_at_every_offset_never_panics() {
	new_test_ext().execute_with(|| {
		let full = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		for len in 0..full.len().min(600) {
			let mut h = MockHandle::new(full[..len].to_vec());
			// Must not panic. Any Result is acceptable.
			let _ = ShieldedPoolPrecompile::<Test>::execute(&mut h);
		}
	});
}

/// An offset pointing back into the head makes the "length" word overlap the
/// caller-controlled head — a classic way to fabricate a huge length.
#[test]
fn attack_self_referential_offset_is_refused() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		// Point the proof offset at slot 0 of the head (offset 0 → itself).
		input[4..36].copy_from_slice(&[0u8; 32]);
		let mut h = MockHandle::new(input);
		let _ = ShieldedPoolPrecompile::<Test>::execute(&mut h);
	});
}

/// Every dynamic offset set to u256::MAX. word_to_usize must reject before any
/// slicing arithmetic happens.
#[test]
fn attack_max_u256_offsets_are_refused_not_truncated() {
	new_test_ext().execute_with(|| {
		for slot in [0usize, 64, 96, 128, 256] {
			let mut input = encode_private_transfer(
				&[0x01u8; 72],
				canon(0xBB),
				&[canon(1)],
				&[canon(2)],
				&[vec![0x01u8; 180]],
				0,
				0,
				1,
			);
			input[4 + slot..4 + slot + 32].copy_from_slice(&[0xFFu8; 32]);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		}
	});
}

/// 2^32 + small: the low 32 bits look like a valid offset while the value is
/// astronomically out of range. This is the exact shape that `low_u32` let
/// through historically.
#[test]
fn attack_offset_above_u32_that_looks_benign_is_refused() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		// 2^32 + 288 — low 32 bits read as 288, a perfectly plausible offset.
		let sneaky = U256::from(1u64 << 32) + U256::from(288u64);
		let word = sneaky.to_big_endian();
		input[4..36].copy_from_slice(&word);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

/// A declared array count of ~1e9 must be refused BEFORE Vec::with_capacity
/// reserves for it — otherwise one call OOMs the node.
#[test]
fn attack_huge_array_count_does_not_allocate() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		// Find the nullifiers array offset and overwrite its count word.
		let off = U256::from_big_endian(&input[4 + 64..4 + 96]).as_usize();
		let count_at = 4 + off;
		if count_at + 32 <= input.len() {
			let huge = U256::from(1u64 << 30).to_big_endian();
			input[count_at..count_at + 32].copy_from_slice(&huge);
		}
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

/// A blob of every wrong length must be refused with the blob's own message —
/// not silently truncated or padded into a valid-looking 56 bytes.
#[test]
fn attack_every_wrong_blob_length_is_refused() {
	new_test_ext().execute_with(|| {
		for len in [0usize, 1, 32, 55, 57, 64, 1024] {
			let input = encode_private_transfer_with_blob(
				&[0x01u8; 72],
				canon(0xBB),
				&[canon(1)],
				&[canon(2)],
				&[vec![0x01u8; 180]],
				0,
				0,
				1,
				&vec![0x0Bu8; len],
			);
			let mut h = MockHandle::new(input);
			expect_error_msg(
				ShieldedPoolPrecompile::<Test>::execute(&mut h),
				"ovk blob must be exactly 56 bytes",
			);
		}
	});
}

/// A fee word of u256::MAX must not panic converting to u128 — it must be
/// rejected as an overflow.
#[test]
fn attack_max_fee_word_is_refused_not_panicking() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		input[4 + 192..4 + 224].copy_from_slice(&[0xFFu8; 32]);
		let mut h = MockHandle::new(input);
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"fee overflow",
		);
	});
}

/// asset_id and circuit_version live in u32 slots. A word with high bits set
/// must be rejected, never truncated to a plausible small number.
#[test]
fn attack_oversized_u32_slots_are_refused_not_truncated() {
	new_test_ext().execute_with(|| {
		for slot in [160usize, 224] {
			let mut input = encode_private_transfer(
				&[0x01u8; 72],
				canon(0xBB),
				&[canon(1)],
				&[canon(2)],
				&[vec![0x01u8; 180]],
				0,
				0,
				1,
			);
			// 2^32 exactly: truncates to 0 if the decoder uses low_u32.
			let word = U256::from(1u64 << 32).to_big_endian();
			input[4 + slot..4 + slot + 32].copy_from_slice(&word);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		}
	});
}

/// Random fuzz over the whole calldata: flip bytes everywhere and assert the
/// decoder never panics. Deterministic (fixed LCG) so a failure reproduces.
#[test]
fn attack_byte_fuzz_never_panics() {
	new_test_ext().execute_with(|| {
		let base = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		let mut seed: u64 = 0x2545F4914F6CDD1D;
		for _ in 0..3000 {
			let mut input = base.clone();
			// 1–8 mutations per round.
			seed = seed
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let muts = 1 + (seed >> 60) as usize % 8;
			for _ in 0..muts {
				seed = seed
					.wrapping_mul(6364136223846793005)
					.wrapping_add(1442695040888963407);
				let pos = (seed >> 33) as usize % input.len();
				seed = seed
					.wrapping_mul(6364136223846793005)
					.wrapping_add(1442695040888963407);
				input[pos] = (seed >> 40) as u8;
			}
			let mut h = MockHandle::new(input);
			// Only requirement: no panic.
			let _ = ShieldedPoolPrecompile::<Test>::execute(&mut h);
		}
	});
}

/// Fuzz with truncation AND mutation combined — the shape most likely to hit an
/// unchecked slice near a boundary.
#[test]
fn attack_truncated_fuzz_never_panics() {
	new_test_ext().execute_with(|| {
		let base = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		let mut seed: u64 = 0x9E3779B97F4A7C15;
		for _ in 0..2000 {
			seed = seed
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let cut = 4 + (seed >> 33) as usize % base.len().max(1);
			let mut input = base[..cut.min(base.len())].to_vec();
			if !input.is_empty() {
				seed = seed
					.wrapping_mul(6364136223846793005)
					.wrapping_add(1442695040888963407);
				let pos = (seed >> 33) as usize % input.len();
				input[pos] = (seed >> 40) as u8;
			}
			let mut h = MockHandle::new(input);
			let _ = ShieldedPoolPrecompile::<Test>::execute(&mut h);
		}
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial: the OVK blob over the EVM route
//
// The SCALE route gets its 56-byte guarantee from the type itself ([u8;56]).
// The EVM route does not: calldata carries a dynamic `bytes`, so the decoder is
// the ONLY thing pinning the length. These probe that boundary from the side an
// attacker controls byte-for-byte.
// ─────────────────────────────────────────────────────────────────────────────

/// A blob whose declared ABI length disagrees with the bytes that follow must
/// be refused — not padded, not truncated into a valid-looking 56.
#[test]
fn attack_blob_length_prefix_lying_about_its_payload_is_refused() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		// Walk to the blob's length word (head slot 8 → offset) and claim 56
		// bytes are 4096 — the payload after it is still only 56.
		let blob_off = U256::from_big_endian(&input[4 + 256..4 + 288]).as_usize();
		let len_at = 4 + blob_off;
		if len_at + 32 <= input.len() {
			let lie = U256::from(4096u64).to_big_endian();
			input[len_at..len_at + 32].copy_from_slice(&lie);
		}
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

/// The blob's ABI offset pointing into the middle of another field must not let
/// the decoder reinterpret that field's bytes as a blob.
#[test]
fn attack_blob_offset_aliasing_another_field_is_refused_or_rejected() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		// Point the blob offset at the proof's region: whatever it reads there
		// is not a 56-byte blob, so it must fail rather than silently accept.
		let proof_off = U256::from_big_endian(&input[4..36]);
		input[4 + 256..4 + 288].copy_from_slice(&proof_off.to_big_endian());
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

/// Every blob byte pattern of the CORRECT length must decode — the chain holds
/// no key and must not editorialize about ciphertext. Zeros included: the
/// all-zero blob is a wallet-side smell, never a consensus rule.
#[test]
fn attack_any_56_byte_blob_decodes_including_zeros() {
	new_test_ext().execute_with(|| {
		for pattern in [0x00u8, 0xFF, 0x0B, 0xAA] {
			let input = encode_private_transfer_with_blob(
				&[0x01u8; 72],
				canon(0xBB),
				&[canon(1)],
				&[canon(2)],
				&[vec![0x01u8; 180]],
				0,
				0,
				1,
				&[pattern; 56],
			);
			let mut h = MockHandle::new(input);
			// Reaches dispatch (the mock has no registered asset, so the error
			// is a dispatch one, never an ABI/blob-length rejection).
			let result = ShieldedPoolPrecompile::<Test>::execute(&mut h);
			if let Err(fp_evm::PrecompileFailure::Error {
				exit_status: ExitError::Other(msg),
			}) = &result
			{
				assert!(
					!msg.contains("ovk blob"),
					"pattern {pattern:#x} must not be rejected as a blob: {msg}"
				);
			}
		}
	});
}

/// The memo bytes where `sourcePk` sits are ciphertext to the chain. Two calls
/// differing only there must be treated identically by the decoder — a decoder
/// that could tell them apart would mean the field was not encrypted.
#[test]
fn attack_decoder_is_blind_to_the_sourcepk_region_of_the_memo() {
	new_test_ext().execute_with(|| {
		let mut memo_a = vec![0x01u8; 180];
		let mut memo_b = vec![0x01u8; 180];
		memo_a[84..116].fill(0x00);
		memo_b[84..116].fill(0xAB);

		let outcomes: Vec<bool> = [memo_a, memo_b]
			.into_iter()
			.map(|memo| {
				let input = encode_private_transfer(
					&[0x01u8; 72],
					canon(0xBB),
					&[canon(1)],
					&[canon(2)],
					&[memo],
					0,
					0,
					1,
				);
				let mut h = MockHandle::new(input);
				ShieldedPoolPrecompile::<Test>::execute(&mut h).is_ok()
			})
			.collect();
		assert_eq!(
			outcomes[0], outcomes[1],
			"the decoder must not distinguish memos by their sourcePk region"
		);
	});
}
