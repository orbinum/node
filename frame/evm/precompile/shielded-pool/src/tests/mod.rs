//! Precompile tests, split by call and concern, plus the shared helpers and ABI encoders.

use fp_evm::{Precompile, PrecompileFailure};
use sp_core::U256;

use crate::{
	mock::{
		new_test_ext, pending_relay_fees, recorded_commits, registered_relayer,
		set_pending_relay_fees, MockHandle, Test,
	},
	ShieldedPoolPrecompile,
};

mod abi;
mod adversarial;
mod flows;
mod private_transfer;
mod relay;
mod shield;
mod unshield;

/// A distinct, canonical 32-byte field value for `seed`.
///
/// Commitments and nullifiers are checked against the BN254 modulus, and a
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

/// A rejection. Decode and pallet errors alike surface as `Revert`.
fn expect_error(result: Result<fp_evm::PrecompileOutput, PrecompileFailure>) {
	assert!(
		matches!(result, Err(PrecompileFailure::Revert { .. })),
		"expected a revert, got: {result:?}"
	);
}

/// Like [`expect_error`], but pins WHICH rejection fired. The adversarial tests
/// need this: a decoder that refuses everything would pass a bare `is_err`, so
/// the message is what proves the intended check ran.
fn expect_error_msg(result: Result<fp_evm::PrecompileOutput, PrecompileFailure>, needle: &str) {
	let msg = match result {
		Err(PrecompileFailure::Revert { output, .. }) => {
			String::from_utf8_lossy(&output).into_owned()
		}
		other => panic!("expected a revert, got: {other:?}"),
	};
	assert!(
		msg.contains(needle),
		"expected an error containing {needle:?}, got: {msg:?}"
	);
}

/// A dispatch that went through.
fn assert_success(result: Result<fp_evm::PrecompileOutput, PrecompileFailure>) {
	match result {
		Ok(out) => assert_eq!(out.exit_status, fp_evm::ExitSucceed::Stopped),
		Err(e) => panic!("expected successful dispatch, got error: {e:?}"),
	}
}

/// Maps an abi helper's `Result<T, PrecompileFailure>` onto a precompile result,
/// so `expect_error` accepts it.
fn lift<T>(r: Result<T, PrecompileFailure>) -> Result<fp_evm::PrecompileOutput, PrecompileFailure> {
	r.map(|_| fp_evm::PrecompileOutput {
		exit_status: fp_evm::ExitSucceed::Stopped,
		output: vec![],
	})
}

// ─── Low-level ABI encoding ──────────────────────────────────────────────────

/// A 32-byte big-endian ABI word holding `value`.
fn u256_word(value: usize) -> [u8; 32] {
	U256::from(value).to_big_endian()
}

/// [`u256_word`] for a `u128`.
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

/// `shield(uint32,bytes32,bytes,bytes,uint32)` with a well-formed proof at version 1.
fn encode_shield(asset_id: u32, commitment: [u8; 32], memo: &[u8]) -> Vec<u8> {
	encode_shield_with(asset_id, commitment, memo, &[0x01; 128], 1)
}

/// `shield(uint32,bytes32,bytes,bytes,uint32)`, selector `0xf25897e0`.
fn encode_shield_with(
	asset_id: u32,
	commitment: [u8; 32],
	memo: &[u8],
	proof: &[u8],
	circuit_version: u32,
) -> Vec<u8> {
	let memo_enc = encode_bytes(memo);
	let head_size = 160usize;

	let mut input = crate::calls::shield::SELECTOR.to_vec();
	let mut head = vec![0u8; head_size];
	head[28..32].copy_from_slice(&asset_id.to_be_bytes());
	head[32..64].copy_from_slice(&commitment);
	head[64..96].copy_from_slice(&u256_word(head_size));
	head[96..128].copy_from_slice(&u256_word(head_size + memo_enc.len()));
	head[156..160].copy_from_slice(&circuit_version.to_be_bytes());
	input.extend_from_slice(&head);
	input.extend_from_slice(&memo_enc);
	input.extend_from_slice(&encode_bytes(proof));
	input
}

/// `privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)`,
/// selector `0x66ed2cd4`.
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

	// head: 8 slots × 32 = 256 bytes
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

/// `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)`,
/// selector `0x4e505348`.
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
	// head: 10 slots × 32 = 320 bytes; tails (proof, memo) appended after.
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

/// `commitRelay(bytes32[])`, selector `0xc9b235ff`.
fn encode_commit_relay(commits: &[[u8; 32]]) -> Vec<u8> {
	let mut input = vec![0xc9, 0xb2, 0x35, 0xff];
	input.extend_from_slice(&u256_word(32));
	input.extend_from_slice(&encode_bytes32_array(commits));
	input
}

/// `claimRelayFees(uint32,uint256)`, selector `0x2a3274dd`.
fn encode_claim_relay_fees(asset_id: u32, amount: u128) -> Vec<u8> {
	let mut input = vec![0x2a, 0x32, 0x74, 0xdd];
	let mut asset = [0u8; 32];
	asset[28..32].copy_from_slice(&asset_id.to_be_bytes());
	input.extend_from_slice(&asset);
	input.extend_from_slice(&u256_word_u128(amount));
	input
}

// ─── Pool state ──────────────────────────────────────────────────────────────

/// Shields `value` of asset 0 into `commitment` through the precompile.
fn do_shield(commitment: [u8; 32], value: u128) {
	let input = encode_shield(0, commitment, &[0xAB; 180]);
	let mut h = MockHandle::with_value(input, value);
	assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));
}

/// The pool's current Merkle root.
fn current_root() -> [u8; 32] {
	pallet_shielded_pool::Pallet::<Test>::poseidon_root()
}

/// The mock EVM caller's account, as an `unshield` recipient.
fn recipient_bytes() -> [u8; 32] {
	let mut r = [0u8; 32];
	r.copy_from_slice(crate::mock::caller_account().as_ref());
	r
}
