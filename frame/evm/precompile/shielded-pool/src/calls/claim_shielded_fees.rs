//! ABI decoding and call construction for
//! `claimShieldedFees(bytes32,uint256,uint32,bytes,bytes,bytes)`.
//!
//! ## Selector
//! `keccak256("claimShieldedFees(bytes32,uint256,uint32,bytes,bytes,bytes)")[0..4]`
//! = `0x42e1e74c`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field              |
//! |-------------|-----------|--------------------|
//! | 0..32       | `bytes32` | `commitment`       |
//! | 32..64      | `uint256` | `amount`           |
//! | 64..96      | `uint32`  | `asset_id`         |
//! | 96..128     | `uint256` | offset → `memo`    |
//! | 128..160    | `uint256` | offset → `proof`   |
//! | 160..192    | `uint256` | offset → `public_signals` |
//!
//! The **validator** origin is derived from `handle.context().caller`
//! (the EVM address that sent the transaction), mapped to an `AccountId`
//! via `AddressMapping`.  It must match the address registered in
//! `pallet-relayer` that has accumulated pending fees.
//!
//! ## public_signals layout (76 bytes, off-chain encoded)
//! `commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]`

use alloc::vec::Vec;

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};
use sp_core::U256;

use crate::abi;

/// `keccak256("claimShieldedFees(bytes32,uint256,uint32,bytes,bytes,bytes)")[0..4]`
pub const SELECTOR: [u8; 4] = [0x42, 0xe1, 0xe7, 0x4c];

/// Maximum byte length of a serialised Groth16 proof accepted by the pallet.
const MAX_PROOF_LEN: u32 = 512;

/// Decodes the ABI-encoded `input` and returns a ready-to-dispatch
/// `claim_shielded_fees` call.
///
/// The validator `AccountId` is NOT part of the ABI — it is derived from
/// `handle.context().caller` so the pallet can look up the correct pending
/// fee balance in `pallet-relayer`.
pub fn decode<T>(
	_handle: &impl PrecompileHandle,
	input: &[u8],
) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	// Minimum head section: 6 fixed slots × 32 bytes = 192 bytes.
	let params = &input[4..];
	if params.len() < 192 {
		return Err(err("claimShieldedFees: input too short"));
	}

	let commitment = pallet_shielded_pool::Commitment::from(abi::read_bytes32(params, 0)?);

	// Reject zero-amount calls early.
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

	let asset_id = abi::decode_u32(&params[64..96])?;

	let memo_bytes: Vec<u8> = abi::decode_bytes_at_slot(params, 96)?;
	let memo = pallet_shielded_pool::FrameEncryptedMemo::new(memo_bytes)
		.map_err(|_| err("claimShieldedFees: memo too long or wrong size"))?;

	let proof: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<MAX_PROOF_LEN>> =
		abi::decode_bytes_at_slot(params, 128)?
			.try_into()
			.map_err(|_| err("claimShieldedFees: proof too long"))?;

	if proof.is_empty() {
		return Err(err("claimShieldedFees: proof must be non-empty"));
	}

	let public_signals: Vec<u8> = abi::decode_bytes_at_slot(params, 160)?;

	if public_signals.len() != 76 {
		return Err(err("claimShieldedFees: public_signals must be 76 bytes"));
	}

	Ok(pallet_shielded_pool::Call::<T>::claim_shielded_fees {
		commitment,
		amount,
		asset_id,
		memo,
		proof: proof.into(),
		public_signals,
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
	/// ABI head (192 bytes after selector):
	/// `[commitment(32) | amount(32) | asset_id(32) | off_memo(32) | off_proof(32) | off_ps(32)]`
	fn encode_claim_shielded_fees(
		commitment: [u8; 32],
		amount: u128,
		asset_id: u32,
		memo: &[u8],
		proof: &[u8],
		public_signals: &[u8],
	) -> Vec<u8> {
		let memo_enc = encode_bytes(memo);
		let proof_enc = encode_bytes(proof);
		let ps_enc = encode_bytes(public_signals);

		// 6 fixed head slots × 32 bytes = 192
		let head_size = 192usize;
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
			);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		});
	}
}
