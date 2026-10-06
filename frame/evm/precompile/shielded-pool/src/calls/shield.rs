//! ABI decoding and call construction for `shield(uint32,bytes32,bytes,bytes,uint32)`.
//!
//! ## Selector
//! `keccak256("shield(uint32,bytes32,bytes,bytes,uint32)")[0..4]` = `0xf25897e0`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field             |
//! |--------------|-----------|-------------------|
//! | 0..32        | `uint32`  | `asset_id`        |
//! | 32..64       | `bytes32` | `commitment`      |
//! | 64..96       | `uint256` | offset → memo     |
//! | 96..128      | `uint256` | offset → proof    |
//! | 128..160     | `uint32`  | `circuit_version` |
//!
//! ## Notes
//! `amount` is not in the ABI: it is `msg.value`, which the EVM executor has
//! already transferred to the precompile's address before `execute` runs. The
//! proof binds the commitment to that amount.

use fp_evm::{PrecompileFailure, PrecompileHandle};

use super::{balance, params, proof};
use crate::{abi, revert};

/// Selector for the signature in this module's header.
pub const SELECTOR: [u8; 4] = [0xf2, 0x58, 0x97, 0xe0];

/// Decodes `input` into a ready-to-dispatch `shield` call.
///
/// `handle` supplies the amount via `apparent_value` (`msg.value`); the calldata
/// carries the asset, the commitment, the memo and the shield proof.
pub fn decode<T>(
	handle: &impl PrecompileHandle,
	input: &[u8],
) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	// Step 1: require the five-slot head. The memo and proof offsets it carries
	// are bounds checked by their tail decoders.
	let params = params(input, 160, "shield: input too short")?;

	// Step 2: asset_id.
	let asset_id = abi::read_u32(params, 0)?;

	// Step 3: amount, taken from msg.value rather than the calldata. Zero is
	// rejected here as well as in the pallet — it would mint a commitment backed
	// by no funds.
	let apparent_value = handle.context().apparent_value;
	if apparent_value.is_zero() {
		return Err(revert("shield: amount must be non-zero"));
	}
	let amount = balance::<T>(
		apparent_value,
		"shield: msg.value overflow",
		"shield: amount conversion failed",
	)?;

	// Step 4: commitment of the note being created.
	let commitment = pallet_shielded_pool::Commitment::from(abi::read_bytes32(params, 32)?);

	// Step 5: encrypted_memo — dynamic, offset at slot 64. It carries the only
	// copy of the new note's secrets, so a malformed one fails the call.
	let memo_bytes = abi::decode_bytes_at_slot(params, 64)?;
	let encrypted_memo = pallet_shielded_pool::FrameEncryptedMemo::new(memo_bytes)
		.map_err(|_| revert("shield: memo too long or wrong size"))?;

	// Step 6: proof — dynamic, offset at slot 96.
	let proof = proof(
		params,
		96,
		"shield: proof too long",
		"shield: proof must be non-empty",
	)?;

	// Step 7: circuit_version.
	let circuit_version = abi::read_u32(params, 128)?;

	Ok(pallet_shielded_pool::Call::<T>::shield {
		asset_id,
		amount,
		commitment,
		encrypted_memo,
		proof,
		circuit_version,
	})
}
