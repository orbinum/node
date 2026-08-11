//! ABI decoding and call construction for `shield(uint32,bytes32,bytes)`.
//!
//! ## Selector
//! `keccak256("shield(uint32,bytes32,bytes)")[0..4]` = `0x9feb22ea`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field            |
//! |--------------|-----------|------------------|
//! | 0..32        | `uint32`  | `asset_id`       |
//! | 32..64       | `bytes32` | `commitment`     |
//! | 64..96       | `uint256` | offset → memo    |
//!
//! ## Notes
//! `amount` is not in the ABI: it is `msg.value`, which the EVM executor has
//! already transferred to the precompile's address before `execute` runs.

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};

use crate::abi;

/// Selector for the signature in this module's header.
pub const SELECTOR: [u8; 4] = [0x9f, 0xeb, 0x22, 0xea];

/// Decodes `input` into a ready-to-dispatch `shield` call.
///
/// `handle` supplies the amount via `apparent_value` (`msg.value`); the calldata
/// carries only the asset, the commitment, and the memo.
pub fn decode<T>(
	handle: &impl PrecompileHandle,
	input: &[u8],
) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	let params = &input[4..];

	// Step 1: require the three-slot head. The memo offset it carries is bounds
	// checked by the tail decoder in step 5.
	if params.len() < 96 {
		return Err(err("shield: input too short"));
	}

	// Step 2: asset_id.
	let asset_id = abi::decode_u32(&params[0..32])?;

	// Step 3: amount, taken from msg.value rather than the calldata. Zero is
	// rejected here as well as in the pallet — it would mint a commitment backed
	// by no funds.
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

	// Step 4: commitment of the note being created.
	let commitment = pallet_shielded_pool::Commitment::from(abi::read_bytes32(params, 32)?);

	// Step 5: encrypted_memo — dynamic, offset at slot 64. It carries the only
	// copy of the new note's secrets, so a malformed one fails the call.
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
