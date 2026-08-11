//! ABI decoding and call construction for
//! `privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32,bytes)`.
//!
//! ## Selector
//! `keccak256("privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32,bytes)")[0..4]`
//! = `0x1ec439cf`
//!
//! ## ABI layout (`input[4..]`) — standard head/tail encoding
//!
//! Nine 32-byte head slots. Dynamic types (`bytes`, arrays) store an OFFSET
//! here and their real data in the tail; fixed types are inline. The `#` column
//! matches the numbered steps in [`decode`] below, so the layout and the code
//! that reads it stay in the same order.
//!
//! | # | Slot (bytes) | Type      | Field                |
//! |---|--------------|-----------|----------------------|
//! | 1 | 0..32        | `uint256` | offset → `proof`     |
//! | 2 | 32..64       | `bytes32` | `merkle_root`        |
//! | 3 | 64..96       | `uint256` | offset → nullifiers  |
//! | 4 | 96..128      | `uint256` | offset → commitments |
//! | 5 | 128..160     | `uint256` | offset → memos       |
//! | 7 | 160..192     | `uint32`  | `asset_id`           |
//! | 8 | 192..224     | `uint256` | `fee`                |
//! | 9 | 224..256     | `uint32`  | `circuit_version`    |
//! | 10| 256..288     | `uint256` | offset → `ovk_blob`  |
//!
//! Step 6 has no slot of its own: it cross-checks the three arrays decoded in
//! steps 3–5 against each other.
//!
//! `relayer` is not in the ABI at all — it is taken from
//! `handle.context().caller`, so a caller cannot name someone else as the fee
//! recipient (step 11).

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};
use frame_support::BoundedVec;
use sp_core::U256;

use crate::abi;

/// `keccak256("privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32,bytes)")[0..4]`
///
/// Two arguments are easy to misread from the signature alone: the `uint32`
/// before the final `bytes` is `circuitVersion` (the version the spent notes
/// were created under, so the proof is verified against that version's VK), and
/// the trailing `bytes` is the 56-byte OVK blob.
pub const SELECTOR: [u8; 4] = [0x1e, 0xc4, 0x39, 0xcf];

/// Maximum byte length of a serialised Groth16 proof accepted by the pallet.
const MAX_PROOF_LEN: u32 = 512;
/// Maximum number of input nullifiers / output commitments in a single transfer.
const MAX_NOTES: u32 = 2;
/// Minimum `params` length: nine 32-byte head slots. Every fixed-offset read
/// below is covered by this one gate, so it must stay in step with the table.
const HEAD_SIZE: usize = 288;

/// Decodes the ABI-encoded `input` and returns a ready-to-dispatch
/// `private_transfer` call.
///
/// The steps below are numbered to match the ABI table in the module header.
/// Order is not arbitrary: the cheap length gate runs first (step 0) so a
/// malformed call is rejected before any allocation, and the structural checks
/// (step 6) run before the fee and blob work, so a nonsensical call never
/// reaches the pallet.
///
/// Everything here decodes UNTRUSTED calldata — an EVM caller controls every
/// byte — so each helper is bounds-checked and every word is rejected rather
/// than truncated when it does not fit its declared type.
pub fn decode<T>(
	handle: &impl PrecompileHandle,
	input: &[u8],
) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	let params = &input[4..];

	// ── 0. Head gate ─────────────────────────────────────────────────────────
	// One length check covering every fixed-offset read below, done before any
	// decoding so malformed calldata costs nothing.
	if params.len() < HEAD_SIZE {
		return Err(err("privateTransfer: input too short"));
	}

	// ── 1. proof (slot 0 → tail) ─────────────────────────────────────────────
	// Bounded on the way in: `MAX_PROOF_LEN` is the pallet's ceiling, so an
	// oversized proof is refused here rather than at dispatch. Empty is refused
	// separately — the ZK verifier would reject it anyway, but far later and
	// with a worse message.
	let proof: BoundedVec<u8, frame_support::traits::ConstU32<MAX_PROOF_LEN>> =
		abi::decode_bytes_at_slot(params, 0)?
			.try_into()
			.map_err(|_| err("privateTransfer: proof too long"))?;

	if proof.is_empty() {
		return Err(err("privateTransfer: proof must be non-empty"));
	}

	// ── 2. merkle_root (slot 1, inline) ──────────────────────────────────────
	let merkle_root: pallet_shielded_pool::Hash = abi::read_bytes32(params, 32)?;

	// ── 3. nullifiers (slot 2 → tail) ────────────────────────────────────────
	let nullifiers: BoundedVec<
		pallet_shielded_pool::Nullifier,
		frame_support::traits::ConstU32<MAX_NOTES>,
	> = abi::decode_bytes32_array_at_slot(params, 64)?
		.into_iter()
		.map(pallet_shielded_pool::Nullifier::from)
		.collect::<alloc::vec::Vec<_>>()
		.try_into()
		.map_err(|_| err("privateTransfer: too many nullifiers"))?;

	// ── 4. commitments (slot 3 → tail) ───────────────────────────────────────
	let commitments: BoundedVec<
		pallet_shielded_pool::Commitment,
		frame_support::traits::ConstU32<MAX_NOTES>,
	> = abi::decode_bytes32_array_at_slot(params, 96)?
		.into_iter()
		.map(pallet_shielded_pool::Commitment::from)
		.collect::<alloc::vec::Vec<_>>()
		.try_into()
		.map_err(|_| err("privateTransfer: too many commitments"))?;

	// ── 5. encrypted_memos (slot 4 → tail) ───────────────────────────────────
	let encrypted_memos: BoundedVec<
		pallet_shielded_pool::FrameEncryptedMemo,
		frame_support::traits::ConstU32<MAX_NOTES>,
	> = abi::decode_bytes_array_at_slot(params, 128)?
		.into_iter()
		.map(|m| {
			pallet_shielded_pool::FrameEncryptedMemo::new(m)
				.map_err(|_| err("privateTransfer: memo too long"))
		})
		.collect::<Result<alloc::vec::Vec<_>, _>>()?
		.try_into()
		.map_err(|_| err("privateTransfer: too many memos"))?;

	// ── 6. Structural consistency across steps 3–5 ───────────────────────────
	// The three arrays run in parallel — input i, output i, memo i — so a length
	// mismatch is a call that cannot mean anything. The ZK proof enforces value
	// balance, not array arity, and the pallet re-checks this; catching it here
	// keeps a nonsensical call from consuming dispatch weight at all.
	if nullifiers.is_empty() {
		return Err(err("privateTransfer: at least one nullifier required"));
	}
	if nullifiers.len() != commitments.len() {
		return Err(err("privateTransfer: nullifier/commitment count mismatch"));
	}
	if commitments.len() != encrypted_memos.len() {
		return Err(err("privateTransfer: commitment/memo count mismatch"));
	}

	// ── 7. asset_id (slot 5, inline) ─────────────────────────────────────────
	let asset_id = abi::decode_u32(&params[160..192])?;

	// ── 8. fee (slot 6, inline) ──────────────────────────────────────────────
	// Two narrowing steps, both fallible: the ABI word is a `uint256` while the
	// pallet's balance is at most `u128`. `try_into` rather than `as_u128()`,
	// which panics above 2^128 — and this word is fully caller-controlled.
	let fee: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = U256::from_big_endian(&params[192..224])
			.try_into()
			.map_err(|_| err("privateTransfer: fee overflow"))?;
		raw.try_into()
			.map_err(|_| err("privateTransfer: fee conversion failed"))?
	};

	// ── 9. circuit_version (slot 7, inline) ──────────────────────────────────
	let circuit_version = abi::decode_u32(&params[224..256])?;

	// ── 10. ovk_blob (slot 8 → tail) ─────────────────────────────────────────
	// Calldata carries a dynamic `bytes`, so this is where the 56-byte length is
	// pinned on the EVM route — the SCALE route gets it from the type itself.
	// Length is ALL that is checked: the blob is ciphertext and no key exists on
	// chain, so any 56 bytes are valid, zeros included.
	let ovk_blob = {
		let raw = abi::decode_bytes_at_slot(params, 256)?;
		pallet_shielded_pool::OvkBlob::from_bytes(&raw)
			.map_err(|_| err("privateTransfer: ovk blob must be exactly 56 bytes"))?
	};

	// ── 11. relayer — from the CALLER, never from calldata ────────────────────
	// Taking this from the ABI would let anyone name a third party as the fee
	// recipient. `pallet-relayer` resolves the caller's registered Substrate
	// account from it.
	let relayer = Some(handle.context().caller);

	Ok(pallet_shielded_pool::Call::<T>::private_transfer {
		proof,
		merkle_root,
		nullifiers,
		commitments,
		encrypted_memos,
		asset_id,
		fee,
		relayer,
		circuit_version,
		ovk_blob,
	})
}

// ─────────────────────────────────────────────────────────────────────────────

fn err(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}
