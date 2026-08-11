//! ABI decoding and call construction for `shield(uint32,bytes32,bytes)`.
//!
//! ## Selector
//! `keccak256("shield(uint32,bytes32,bytes)")[0..4]` = `0x9feb22ea`
//!
//! ## ABI layout (`input[4..]`) — standard head/tail encoding
//!
//! Three 32-byte head slots. The dynamic `bytes` stores an OFFSET here and its
//! real data in the tail; fixed types are inline. The `#` column matches the
//! numbered steps in [`decode`] below, so the layout and the code that reads it
//! stay in the same order.
//!
//! | # | Slot (bytes) | Type      | Field            |
//! |---|--------------|-----------|------------------|
//! | 1 | 0..32        | `uint32`  | `asset_id`       |
//! | 3 | 32..64       | `bytes32` | `commitment`     |
//! | 4 | 64..96       | `uint256` | offset → memo    |
//! |   | at offset    | `bytes`   | `encrypted_memo` |
//!
//! Step 2 has no slot: the token **amount** is not in the ABI at all. It comes
//! from `msg.value` — the EVM executor transfers it to the precompile's address
//! before `execute` runs — which is also why `shield` is the one call here that
//! is payable.

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};

use crate::abi;

/// `keccak256("shield(uint32,bytes32,bytes)")[0..4]`
pub const SELECTOR: [u8; 4] = [0x9f, 0xeb, 0x22, 0xea];

/// Minimum `params` length: three 32-byte head slots. Every fixed-offset read
/// below is covered by this one gate, so it must stay in step with the table.
const HEAD_SIZE: usize = 96;

/// Decodes the ABI-encoded `input` and returns a ready-to-dispatch `shield` call.
///
/// The steps below are numbered to match the ABI table in the module header.
/// `handle` is consulted only for `apparent_value` (the `msg.value` amount),
/// which is step 2 and has no ABI slot.
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
		return Err(err("shield: input too short"));
	}

	// ── 1. asset_id (slot 0, inline) ─────────────────────────────────────────
	let asset_id = abi::decode_u32(&params[0..32])?;

	// ── 2. amount — from msg.value, NOT from calldata ────────────────────────
	// The executor has already moved this to the precompile's address, so it is
	// the one argument a caller cannot lie about. Zero is refused here as
	// defense in depth: the pallet rejects it too, but this fails before
	// dispatch and names the problem.
	let apparent_value = handle.context().apparent_value;
	if apparent_value.is_zero() {
		return Err(err("shield: amount must be non-zero"));
	}

	// Two narrowing steps, both fallible: `msg.value` is a `U256` while the
	// pallet's balance is at most `u128`. `try_into` rather than `as_u128()`,
	// which panics above 2^128.
	let amount: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = apparent_value
			.try_into()
			.map_err(|_| err("shield: msg.value overflow"))?;
		raw.try_into()
			.map_err(|_| err("shield: amount conversion failed"))?
	};

	// ── 3. commitment (slot 1, inline) ───────────────────────────────────────
	// Canonicity is NOT checked here — the pallet does it. `shield` is the least
	// guarded way into the tree (the depositor picks these bytes with no proof
	// constraining them), so that check belongs at the type boundary every route
	// crosses, not in one decoder.
	let commitment = pallet_shielded_pool::Commitment::from(abi::read_bytes32(params, 32)?);

	// ── 4. encrypted_memo (slot 2 → tail) ────────────────────────────────────
	// `FrameEncryptedMemo::new` pins the exact 180-byte size; the chain never
	// reads inside it.
	let memo_bytes = abi::decode_bytes_at_slot(params, 64)?;
	let encrypted_memo = pallet_shielded_pool::FrameEncryptedMemo::new(memo_bytes)
		.map_err(|_| err("shield: memo too long or wrong size"))?;

	Ok(pallet_shielded_pool::Call::<T>::shield {
		asset_id,
		amount,
		commitment,
		encrypted_memo,
	})
}

// ─────────────────────────────────────────────────────────────────────────────

fn err(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}
