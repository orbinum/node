//! Precompile tests, split by concern, plus the shared helpers and ABI encoders.

use fp_evm::{Precompile, PrecompileFailure};
use sp_core::U256;

use crate::{
	mock::{new_test_ext, MockHandle, Test},
	ShieldedPoolPrecompile,
};

mod abi;
mod adversarial;
mod shield;

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

/// Encodes a single `bytes` value: `uint256(length) ++ data ++ zero-padding`.
fn encode_bytes(data: &[u8]) -> Vec<u8> {
	let padded = (data.len() + 31) & !31;
	let mut out = vec![0u8; 32 + padded];
	out[..32].copy_from_slice(&u256_word(data.len()));
	out[32..32 + data.len()].copy_from_slice(data);
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
