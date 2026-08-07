//! ABI decoding and call construction for `shield(uint32,bytes32,bytes)`.
//!
//! ## Selector
//! `keccak256("shield(uint32,bytes32,bytes)")[0..4]` = `0x9feb22ea`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field           |
//! |-------------|-----------|-----------------|
//! | 0..32       | `uint32`  | `asset_id`      |
//! | 32..64      | `bytes32` | `commitment`    |
//! | 64..96      | `uint256` | offset → memo   |
//! | at offset   | `bytes`   | `encrypted_memo`|
//!
//! The token **amount** is read from `msg.value` — the EVM executor transfers it to
//! the precompile's address before `execute` runs, so no explicit amount slot is needed.

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};

use crate::abi;

/// `keccak256("shield(uint32,bytes32,bytes)")[0..4]`
pub const SELECTOR: [u8; 4] = [0x9f, 0xeb, 0x22, 0xea];

/// Decodes the ABI-encoded `input` and returns a ready-to-dispatch `shield` call.
///
/// `handle` is consulted only for `apparent_value` (the `msg.value` ETH amount).
pub fn decode<T>(
	handle: &impl PrecompileHandle,
	input: &[u8],
) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	let params = &input[4..];
	if params.len() < 96 {
		return Err(err("shield: input too short"));
	}

	let asset_id = abi::decode_u32(&params[0..32])?;

	// Reject zero-value calls at the precompile boundary (defense-in-depth;
	// the pallet also rejects them, but this produces a cleaner error before
	// reaching the dispatch layer).
	let apparent_value = handle.context().apparent_value;
	if apparent_value.is_zero() {
		return Err(err("shield: amount must be non-zero"));
	}

	let amount: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = apparent_value
			.try_into()
			.map_err(|_| err("shield: msg.value overflow"))?;
		raw.try_into()
			.map_err(|_| err("shield: amount conversion failed"))?
	};

	let commitment = pallet_shielded_pool::Commitment::from(abi::read_bytes32(params, 32)?);

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
