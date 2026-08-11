//! ABI decoding and call construction for
//! `claimShieldedFees(bytes32,uint256,uint32,bytes,bytes,bytes,uint32)`.
//!
//! ## Selector
//! `keccak256("claimShieldedFees(bytes32,uint256,uint32,bytes,bytes,bytes,uint32)")[0..4]`
//! = `0x88d9deba`
//!
//! ## ABI layout (`input[4..]`) — standard head/tail encoding
//!
//! Seven 32-byte head slots. Dynamic types (`bytes`) store an OFFSET here and
//! their real data in the tail; fixed types are inline. The `#` column matches
//! the numbered steps in [`decode`] below, so the layout and the code that
//! reads it stay in the same order.
//!
//! | # | Slot (bytes) | Type      | Field                     |
//! |---|--------------|-----------|---------------------------|
//! | 1 | 0..32        | `bytes32` | `commitment`              |
//! | 2 | 32..64       | `uint256` | `amount`                  |
//! | 3 | 64..96       | `uint32`  | `asset_id`                |
//! | 4 | 96..128      | `uint256` | offset → `memo`           |
//! | 5 | 128..160     | `uint256` | offset → `proof`          |
//! | 6 | 160..192     | `uint256` | offset → `public_signals` |
//! | 7 | 192..224     | `uint32`  | `circuit_version`         |
//!
//! ## Field notes
//!
//! - **The claiming validator is not in the ABI.** It comes from
//!   `handle.context().caller` — the EVM address that sent the transaction —
//!   mapped to an `AccountId` via `AddressMapping`, and it must match the
//!   address `pallet-relayer` has accumulated pending fees for. Taking it from
//!   calldata would let anyone claim another validator's fees.
//! - **`public_signals`** is a 76-byte off-chain blob, laid out as
//!   `commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]`.
//!   It is what BINDS the head parameters to the proof: the pallet checks that
//!   slots 1–3 match the values embedded here, so a caller cannot present a
//!   valid proof and then claim a different amount or asset with it. Hence the
//!   exact-length check in step 6 — a short blob would leave those comparisons
//!   reading past the end or against garbage.
//!
//! ## Why the length gate is not a single check
//!
//! The head is 224 bytes, but the gate at step 0 only requires 192. That is
//! deliberate: `circuit_version` (slot 7) was appended by a later upgrade, so
//! it is checked where it is read (step 7) and the error names the missing
//! field instead of reporting a generic "too short".

use alloc::vec::Vec;

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};
use sp_core::U256;

use crate::abi;

/// `keccak256("claimShieldedFees(bytes32,uint256,uint32,bytes,bytes,bytes,uint32)")[0..4]`
/// The trailing `uint32` is `circuitVersion` — the circuit version the spent
/// notes were created under, so the proof is verified against that version's VK.
pub const SELECTOR: [u8; 4] = [0x88, 0xd9, 0xde, 0xba];

/// Maximum byte length of a serialised Groth16 proof accepted by the pallet.
const MAX_PROOF_LEN: u32 = 512;

/// Exact length of the `public_signals` blob — see the module header for its
/// layout. Not a maximum: the pallet indexes fixed offsets inside it.
const PUBLIC_SIGNALS_LEN: usize = 76;

/// Minimum `params` length: the six head slots this call has always had.
/// Slot 7 came later and is checked where it is read.
const HEAD_SIZE_BASE: usize = 192;
/// The full seven-slot head, through `circuit_version`.
const HEAD_SIZE_FULL: usize = 224;

/// Decodes the ABI-encoded `input` and returns a ready-to-dispatch
/// `claim_shielded_fees` call.
///
/// The steps below are numbered to match the ABI table in the module header.
/// The validator `AccountId` is NOT part of the ABI — the pallet derives it
/// from `handle.context().caller` to look up the right pending-fee balance in
/// `pallet-relayer`, which is why `_handle` goes unused here.
///
/// Everything here decodes UNTRUSTED calldata — an EVM caller controls every
/// byte — so each helper is bounds-checked and every word is rejected rather
/// than truncated when it does not fit its declared type.
pub fn decode<T>(
	_handle: &impl PrecompileHandle,
	input: &[u8],
) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	let params = &input[4..];

	// ── 0. Head gate ─────────────────────────────────────────────────────────
	// Covers slots 1–6, the reads done unconditionally below. Slot 7 is gated
	// where it is read.
	if params.len() < HEAD_SIZE_BASE {
		return Err(err("claimShieldedFees: input too short"));
	}

	// ── 1. commitment (slot 0, inline) ───────────────────────────────────────
	// The fee note's commitment. Cross-checked against `public_signals[0..32]`
	// by the pallet — see step 6.
	let commitment = pallet_shielded_pool::Commitment::from(abi::read_bytes32(params, 0)?);

	// ── 2. amount (slot 1, inline) ───────────────────────────────────────────
	// Zero is refused before anything else is built: claiming nothing would
	// still insert a leaf and move the Merkle root. Then two fallible narrowing
	// steps — the ABI word is a `uint256` while the pallet's balance is at most
	// `u128`. `try_into` rather than `as_u128()`, which panics above 2^128 on a
	// word the caller fully controls.
	let amount_u256 = U256::from_big_endian(&params[32..64]);
	if amount_u256.is_zero() {
		return Err(err("claimShieldedFees: amount must be non-zero"));
	}
	let amount: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = amount_u256
			.try_into()
			.map_err(|_| err("claimShieldedFees: amount overflow"))?;
		raw.try_into()
			.map_err(|_| err("claimShieldedFees: amount conversion failed"))?
	};

	// ── 3. asset_id (slot 2, inline) ─────────────────────────────────────────
	let asset_id = abi::decode_u32(&params[64..96])?;

	// ── 4. memo (slot 3 → tail) ──────────────────────────────────────────────
	// `FrameEncryptedMemo::new` pins the pallet's exact size; the chain never
	// reads inside it.
	let memo_bytes: Vec<u8> = abi::decode_bytes_at_slot(params, 96)?;
	let memo = pallet_shielded_pool::FrameEncryptedMemo::new(memo_bytes)
		.map_err(|_| err("claimShieldedFees: memo too long or wrong size"))?;

	// ── 5. proof (slot 4 → tail) ─────────────────────────────────────────────
	// Bounded on the way in: `MAX_PROOF_LEN` is the pallet's ceiling, so an
	// oversized proof is refused here rather than at dispatch. Empty is refused
	// separately — the ZK verifier would reject it anyway, but far later.
	let proof: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<MAX_PROOF_LEN>> =
		abi::decode_bytes_at_slot(params, 128)?
			.try_into()
			.map_err(|_| err("claimShieldedFees: proof too long"))?;

	if proof.is_empty() {
		return Err(err("claimShieldedFees: proof must be non-empty"));
	}

	// ── 6. public_signals (slot 5 → tail) ────────────────────────────────────
	// EXACTLY 76 bytes, not "at most": the pallet reads fixed offsets inside
	// this blob to check that steps 1–3 match what the proof actually attests
	// to. A short blob would leave those comparisons reading past the end, and
	// a long one would hide trailing bytes nothing verifies.
	let public_signals_raw: Vec<u8> = abi::decode_bytes_at_slot(params, 160)?;

	if public_signals_raw.len() != PUBLIC_SIGNALS_LEN {
		return Err(err("claimShieldedFees: public_signals must be 76 bytes"));
	}
	let public_signals = public_signals_raw
		.try_into()
		.map_err(|_| err("claimShieldedFees: public_signals too long"))?;

	// ── 7. circuit_version (slot 6, inline) ──────────────────────────────────
	// Appended by a later upgrade, so it gets its own gate with an error that
	// names it rather than a generic "too short".
	if params.len() < HEAD_SIZE_FULL {
		return Err(err(
			"claimShieldedFees: input too short (missing circuitVersion)",
		));
	}
	let circuit_version = abi::decode_u32(&params[192..224])?;

	Ok(pallet_shielded_pool::Call::<T>::claim_shielded_fees {
		commitment,
		amount,
		asset_id,
		memo,
		proof,
		public_signals,
		circuit_version,
	})
}

// ─────────────────────────────────────────────────────────────────────────────

fn err(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use fp_evm::{ExitError, ExitSucceed, Precompile, PrecompileFailure};
	use sp_core::U256;

	use crate::{
		mock::{new_test_ext, set_pending_relay_fees, MockHandle, Test},
		ShieldedPoolPrecompile,
	};

	use super::SELECTOR;

	// ── Assertion helpers ────────────────────────────────────────────────────

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
			Ok(out) => assert_eq!(out.exit_status, ExitSucceed::Stopped),
			Err(e) => panic!("expected successful dispatch, got error: {e:?}"),
		}
	}

	// ── ABI encoder ──────────────────────────────────────────────────────────

	fn u256_word(v: usize) -> [u8; 32] {
		U256::from(v).to_big_endian()
	}

	fn u256_word_u128(v: u128) -> [u8; 32] {
		U256::from(v).to_big_endian()
	}

	/// Encodes a single `bytes` tail: `uint256(length) ++ data ++ zero-padding`.
	fn encode_bytes(data: &[u8]) -> Vec<u8> {
		let padded = (data.len() + 31) & !31;
		let mut out = vec![0u8; 32 + padded];
		out[..32].copy_from_slice(&u256_word(data.len()));
		out[32..32 + data.len()].copy_from_slice(data);
		out
	}

	/// Encodes a full `claimShieldedFees` ABI call (selector + params).
	///
	/// ABI head (224 bytes after selector):
	/// `[commitment(32) | amount(32) | asset_id(32) | off_memo(32) | off_proof(32) | off_ps(32) | circuit_version(32)]`
	fn encode_claim_shielded_fees(
		commitment: [u8; 32],
		amount: u128,
		asset_id: u32,
		memo: &[u8],
		proof: &[u8],
		public_signals: &[u8],
		circuit_version: u32,
	) -> Vec<u8> {
		let memo_enc = encode_bytes(memo);
		let proof_enc = encode_bytes(proof);
		let ps_enc = encode_bytes(public_signals);

		// 7 fixed head slots × 32 bytes = 224 (added trailing uint32 circuitVersion)
		let head_size = 224usize;
		let memo_off = head_size;
		let proof_off = head_size + memo_enc.len();
		let ps_off = head_size + memo_enc.len() + proof_enc.len();

		let mut head = vec![0u8; head_size];
		head[0..32].copy_from_slice(&commitment);
		head[32..64].copy_from_slice(&u256_word_u128(amount));
		head[92..96].copy_from_slice(&asset_id.to_be_bytes()); // right-aligned uint32
		head[96..128].copy_from_slice(&u256_word(memo_off));
		head[128..160].copy_from_slice(&u256_word(proof_off));
		head[160..192].copy_from_slice(&u256_word(ps_off));
		head[220..224].copy_from_slice(&circuit_version.to_be_bytes());

		let mut input = SELECTOR.to_vec();
		input.extend_from_slice(&head);
		input.extend_from_slice(&memo_enc);
		input.extend_from_slice(&proof_enc);
		input.extend_from_slice(&ps_enc);
		input
	}

	/// Builds a valid 76-byte `public_signals` blob consistent with
	/// `(commitment, amount, asset_id)`.
	///
	/// Layout: `commitment[0..32] | value_le[32..40] | asset_id_le[40..44] | owner_hash[44..76]`
	fn make_public_signals(commitment: [u8; 32], amount: u64, asset_id: u32) -> [u8; 76] {
		let mut ps = [0u8; 76];
		ps[0..32].copy_from_slice(&commitment);
		ps[32..40].copy_from_slice(&amount.to_le_bytes());
		ps[40..44].copy_from_slice(&asset_id.to_le_bytes());
		// owner_hash[44..76] can be arbitrary — left as zeros
		ps
	}

	// ── Minimal valid parameters ─────────────────────────────────────────────

	const COMMITMENT: [u8; 32] = [0x11; 32];
	const AMOUNT: u128 = 500;
	const ASSET_ID: u32 = 0;
	const PROOF: &[u8] = &[0x01u8; 128]; // 128 bytes → passes pallet check

	fn valid_memo() -> Vec<u8> {
		vec![0xAB; 176]
	}

	fn valid_public_signals() -> Vec<u8> {
		make_public_signals(COMMITMENT, AMOUNT as u64, ASSET_ID).to_vec()
	}

	fn valid_input() -> Vec<u8> {
		encode_claim_shielded_fees(
			COMMITMENT,
			AMOUNT,
			ASSET_ID,
			&valid_memo(),
			PROOF,
			&valid_public_signals(),
			1,
		)
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Tests: ABI decoder (pure unit tests, no pallet state)
	// ─────────────────────────────────────────────────────────────────────────

	#[test]
	fn decode_rejects_truncated_input() {
		// Input has only selector, no params at all.
		let input = SELECTOR.to_vec();
		let h = MockHandle::new(input.clone());
		let result = super::decode::<Test>(&h, &input);
		assert!(result.is_err(), "expected Err for truncated input");
	}

	#[test]
	fn decode_rejects_input_shorter_than_head() {
		// 4-byte selector + 100-byte body (< 192 required).
		let mut input = SELECTOR.to_vec();
		input.extend_from_slice(&[0u8; 100]);
		let h = MockHandle::new(input.clone());
		let result = super::decode::<Test>(&h, &input);
		assert!(result.is_err());
	}

	#[test]
	fn decode_rejects_zero_amount() {
		let input = encode_claim_shielded_fees(
			COMMITMENT,
			0, // ← zero amount
			ASSET_ID,
			&valid_memo(),
			PROOF,
			&valid_public_signals(),
			1,
		);
		let h = MockHandle::new(input.clone());
		let result = super::decode::<Test>(&h, &input);
		assert!(result.is_err(), "zero amount must be rejected");
	}

	#[test]
	fn decode_rejects_public_signals_not_76_bytes() {
		for bad_len in [0usize, 32, 75, 77, 128] {
			let bad_signals = vec![0xFFu8; bad_len];
			let input = encode_claim_shielded_fees(
				COMMITMENT,
				AMOUNT,
				ASSET_ID,
				&valid_memo(),
				PROOF,
				&bad_signals,
				1,
			);
			let h = MockHandle::new(input.clone());
			let result = super::decode::<Test>(&h, &input);
			assert!(
				result.is_err(),
				"public_signals of len {bad_len} must be rejected"
			);
		}
	}

	#[test]
	fn decode_rejects_proof_exceeding_max_len() {
		// MAX_PROOF_LEN = 512; send 513 bytes.
		let oversized_proof = vec![0x01u8; 513];
		let input = encode_claim_shielded_fees(
			COMMITMENT,
			AMOUNT,
			ASSET_ID,
			&valid_memo(),
			&oversized_proof,
			&valid_public_signals(),
			1,
		);
		let h = MockHandle::new(input.clone());
		let result = super::decode::<Test>(&h, &input);
		assert!(
			result.is_err(),
			"proof exceeding MAX_PROOF_LEN must be rejected"
		);
	}

	#[test]
	fn decode_rejects_empty_proof() {
		let input = encode_claim_shielded_fees(
			COMMITMENT,
			AMOUNT,
			ASSET_ID,
			&valid_memo(),
			&[], // ← empty proof
			&valid_public_signals(),
			1,
		);
		let h = MockHandle::new(input.clone());
		let result = super::decode::<Test>(&h, &input);
		assert!(result.is_err(), "empty proof must be rejected");
	}

	#[test]
	fn decode_accepts_valid_input() {
		let input = valid_input();
		let h = MockHandle::new(input.clone());
		let result = super::decode::<Test>(&h, &input);
		assert!(
			result.is_ok(),
			"valid input must be accepted, got: {result:?}"
		);
	}

	#[test]
	fn decode_round_trips_commitment() {
		let commitment = [0xABu8; 32];
		let input = encode_claim_shielded_fees(
			commitment,
			AMOUNT,
			ASSET_ID,
			&valid_memo(),
			PROOF,
			make_public_signals(commitment, AMOUNT as u64, ASSET_ID).as_ref(),
			1,
		);
		let h = MockHandle::new(input.clone());
		match super::decode::<Test>(&h, &input).unwrap() {
			pallet_shielded_pool::Call::claim_shielded_fees { commitment: c, .. } => {
				assert_eq!(c, pallet_shielded_pool::Commitment::from(commitment));
			}
			_ => panic!("unexpected call variant"),
		}
	}

	#[test]
	fn decode_round_trips_amount() {
		let amount: u128 = 999_999;
		let ps = make_public_signals(COMMITMENT, amount as u64, ASSET_ID);
		let input = encode_claim_shielded_fees(
			COMMITMENT,
			amount,
			ASSET_ID,
			&valid_memo(),
			PROOF,
			ps.as_ref(),
			1,
		);
		let h = MockHandle::new(input.clone());
		match super::decode::<Test>(&h, &input).unwrap() {
			pallet_shielded_pool::Call::claim_shielded_fees { amount: a, .. } => {
				assert_eq!(Into::<u128>::into(a), amount);
			}
			_ => panic!("unexpected call variant"),
		}
	}

	#[test]
	fn decode_round_trips_asset_id() {
		// asset_id = 0 (the only registered asset in the mock genesis).
		let input = encode_claim_shielded_fees(
			COMMITMENT,
			AMOUNT,
			0,
			&valid_memo(),
			PROOF,
			make_public_signals(COMMITMENT, AMOUNT as u64, 0).as_ref(),
			1,
		);
		let h = MockHandle::new(input.clone());
		match super::decode::<Test>(&h, &input).unwrap() {
			pallet_shielded_pool::Call::claim_shielded_fees { asset_id: id, .. } => {
				assert_eq!(id, 0u32);
			}
			_ => panic!("unexpected call variant"),
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Tests: router + dispatch (full precompile execution)
	// ─────────────────────────────────────────────────────────────────────────

	#[test]
	fn router_recognises_claim_shielded_fees_selector() {
		// Sending only the selector (no valid body) must reach the decoder and
		// produce a decode error, NOT "unknown selector".
		new_test_ext().execute_with(|| {
			let mut h = MockHandle::new(SELECTOR.to_vec());
			match ShieldedPoolPrecompile::<Test>::execute(&mut h) {
				Err(PrecompileFailure::Error {
					exit_status: ExitError::Other(msg),
				}) => {
					let s = msg.to_string();
					assert!(
						!s.contains("unknown selector"),
						"selector must be recognised, got: {s}"
					);
				}
				other => panic!("expected a precompile error, got: {other:?}"),
			}
		});
	}

	#[test]
	fn dispatch_rejects_truncated_input() {
		new_test_ext().execute_with(|| {
			let mut h = MockHandle::new(SELECTOR.to_vec());
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}

	#[test]
	fn dispatch_rejects_zero_amount() {
		new_test_ext().execute_with(|| {
			let input = encode_claim_shielded_fees(
				COMMITMENT,
				0,
				ASSET_ID,
				&valid_memo(),
				PROOF,
				&valid_public_signals(),
				1,
			);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}

	#[test]
	fn dispatch_rejects_empty_proof() {
		new_test_ext().execute_with(|| {
			let input = encode_claim_shielded_fees(
				COMMITMENT,
				AMOUNT,
				ASSET_ID,
				&valid_memo(),
				&[],
				&valid_public_signals(),
				1,
			);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}

	#[test]
	fn dispatch_rejects_wrong_public_signals_length() {
		new_test_ext().execute_with(|| {
			// 75 bytes — one byte short
			let bad_ps = vec![0xFFu8; 75];
			let input = encode_claim_shielded_fees(
				COMMITMENT,
				AMOUNT,
				ASSET_ID,
				&valid_memo(),
				PROOF,
				&bad_ps,
				1,
			);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}

	#[test]
	fn dispatch_rejects_commitment_mismatch_in_signals() {
		// signals[0..32] encodes a different commitment than the param.
		new_test_ext().execute_with(|| {
			set_pending_relay_fees(AMOUNT);
			let mismatched = make_public_signals([0xFFu8; 32], AMOUNT as u64, ASSET_ID);
			let input = encode_claim_shielded_fees(
				COMMITMENT, // param commitment ≠ signals commitment
				AMOUNT,
				ASSET_ID,
				&valid_memo(),
				PROOF,
				mismatched.as_ref(),
				1,
			);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}

	#[test]
	fn dispatch_rejects_value_mismatch_in_signals() {
		// signals[32..40] encodes a different amount than the param.
		new_test_ext().execute_with(|| {
			set_pending_relay_fees(AMOUNT);
			let mismatched = make_public_signals(COMMITMENT, (AMOUNT + 1) as u64, ASSET_ID);
			let input = encode_claim_shielded_fees(
				COMMITMENT,
				AMOUNT, // param amount ≠ signals value
				ASSET_ID,
				&valid_memo(),
				PROOF,
				mismatched.as_ref(),
				1,
			);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}

	#[test]
	fn dispatch_rejects_asset_id_mismatch_in_signals() {
		// signals[40..44] encodes a different asset_id than the param.
		new_test_ext().execute_with(|| {
			set_pending_relay_fees(AMOUNT);
			let mismatched = make_public_signals(COMMITMENT, AMOUNT as u64, 99);
			let input = encode_claim_shielded_fees(
				COMMITMENT,
				AMOUNT,
				ASSET_ID, // param asset_id 0 ≠ signals asset_id 99
				&valid_memo(),
				PROOF,
				mismatched.as_ref(),
				1,
			);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}

	#[test]
	fn dispatch_rejects_insufficient_pending_fees() {
		// MockRelayer returns AMOUNT - 1 < AMOUNT → InsufficientPendingFees.
		new_test_ext().execute_with(|| {
			set_pending_relay_fees(AMOUNT - 1);
			let mut h = MockHandle::new(valid_input());
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}

	#[test]
	fn dispatch_happy_path_inserts_commitment_and_emits_event() {
		new_test_ext().execute_with(|| {
			set_pending_relay_fees(AMOUNT);

			let tree_size_before = pallet_shielded_pool::MerkleTreeSize::<Test>::get();

			let mut h = MockHandle::new(valid_input());
			assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

			// Commitment must have been inserted into the Merkle tree.
			let tree_size_after = pallet_shielded_pool::MerkleTreeSize::<Test>::get();
			assert_eq!(
				tree_size_after,
				tree_size_before + 1,
				"one leaf must be added"
			);
			let leaf = pallet_shielded_pool::MerkleLeaves::<Test>::get(tree_size_before).unwrap();
			assert_eq!(
				leaf,
				pallet_shielded_pool::Commitment::from(COMMITMENT),
				"leaf must match the submitted commitment"
			);
		});
	}

	#[test]
	fn dispatch_happy_path_updates_merkle_root() {
		new_test_ext().execute_with(|| {
			set_pending_relay_fees(AMOUNT);
			let root_before = pallet_shielded_pool::Pallet::<Test>::poseidon_root();

			let mut h = MockHandle::new(valid_input());
			assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

			let root_after = pallet_shielded_pool::Pallet::<Test>::poseidon_root();
			assert_ne!(
				root_before, root_after,
				"Merkle root must change after fee claim"
			);
		});
	}

	#[test]
	fn dispatch_happy_path_stores_encrypted_memo() {
		new_test_ext().execute_with(|| {
			set_pending_relay_fees(AMOUNT);

			let mut h = MockHandle::new(valid_input());
			assert_success(ShieldedPoolPrecompile::<Test>::execute(&mut h));

			// The memo must be retrievable by the commitment key.
			let stored = pallet_shielded_pool::CommitmentMemos::<Test>::get(
				pallet_shielded_pool::Commitment::from(COMMITMENT),
			);
			assert!(
				stored.is_some(),
				"encrypted memo must be stored after successful claim"
			);
		});
	}

	#[test]
	fn dispatch_rejects_unregistered_asset() {
		// asset_id 99 is not registered at genesis → InvalidAssetId.
		new_test_ext().execute_with(|| {
			set_pending_relay_fees(AMOUNT);
			let ps = make_public_signals(COMMITMENT, AMOUNT as u64, 99);
			let input = encode_claim_shielded_fees(
				COMMITMENT,
				AMOUNT,
				99, // unregistered
				&valid_memo(),
				PROOF,
				ps.as_ref(),
				1,
			);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}
}
