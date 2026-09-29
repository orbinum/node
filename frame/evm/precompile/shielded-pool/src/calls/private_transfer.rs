//! ABI decoding and call construction for
//! `privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)`.
//!
//! ## Selector
//! `keccak256("privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)")[0..4]`
//! = `0x66ed2cd4`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field                 |
//! |--------------|-----------|-----------------------|
//! | 0..32        | `uint256` | offset → `proof`      |
//! | 32..64       | `bytes32` | `merkle_root`         |
//! | 64..96       | `uint256` | offset → `nullifiers` |
//! | 96..128      | `uint256` | offset → `commitments`|
//! | 128..160     | `uint256` | offset → `memos`      |
//! | 160..192     | `uint32`  | `asset_id`            |
//! | 192..224     | `uint256` | `fee`                 |
//! | 224..256     | `uint32`  | `circuit_version`     |
//!
//! ## Notes
//! The three arrays are parallel: `commitments[i]` and `memos[i]` describe the
//! output note paid for by `nullifiers[i]`, so all three must have equal length.
//!
//! The relay fee recipient is not in the ABI: it is the relayer that recorded a
//! relay commit for this spend (`commitRelay`), whoever submits it.

use alloc::vec::Vec;

use fp_evm::PrecompileFailure;
use frame_support::{traits::ConstU32, BoundedVec};
use pallet_shielded_pool::{
	types::MAX_ENCRYPTED_MEMO_SIZE, Commitment, FrameEncryptedMemo, Nullifier,
};

use super::{balance, params, proof};
use crate::{abi, revert};

/// Selector for the signature in this module's header.
pub const SELECTOR: [u8; 4] = [0x66, 0xed, 0x2c, 0xd4];

/// Maximum number of input nullifiers / output commitments in a single transfer.
pub const MAX_NOTES: u32 = 2;

/// Decodes `input` into a ready-to-dispatch `private_transfer` call.
///
/// Beyond the ABI itself, this enforces the structural invariant the proof does
/// not cover: at least one input note, and the three arrays equal in length.
pub fn decode<T>(input: &[u8]) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	// Step 1: require all eight head slots.
	let params = params(input, 256, "privateTransfer: input too short")?;

	// Step 2: proof — dynamic, offset at slot 0.
	let proof = proof(
		params,
		0,
		"privateTransfer: proof too long",
		"privateTransfer: proof must be non-empty",
	)?;

	// Step 3: merkle_root the proof is verified against.
	let merkle_root: pallet_shielded_pool::Hash = abi::read_bytes32(params, 32)?;

	// Step 4: the three parallel arrays — nullifiers spent, commitments created,
	// and the memo carrying each new note's secrets. The decoders bound count and
	// item size, so the conversions below cannot fail.
	let nullifiers: BoundedVec<Nullifier, ConstU32<MAX_NOTES>> =
		abi::decode_bytes32_array_at_slot(params, 64, MAX_NOTES as usize)?
			.into_iter()
			.map(Nullifier::from)
			.collect::<Vec<_>>()
			.try_into()
			.map_err(|_| revert("privateTransfer: too many nullifiers"))?;

	let commitments: BoundedVec<Commitment, ConstU32<MAX_NOTES>> =
		abi::decode_bytes32_array_at_slot(params, 96, MAX_NOTES as usize)?
			.into_iter()
			.map(Commitment::from)
			.collect::<Vec<_>>()
			.try_into()
			.map_err(|_| revert("privateTransfer: too many commitments"))?;

	let encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<MAX_NOTES>> =
		abi::decode_bytes_array_at_slot(
			params,
			128,
			MAX_NOTES as usize,
			MAX_ENCRYPTED_MEMO_SIZE as usize,
		)?
		.into_iter()
		.map(|m| FrameEncryptedMemo::new(m).map_err(|_| revert("privateTransfer: memo too long")))
		.collect::<Result<Vec<_>, _>>()?
		.try_into()
		.map_err(|_| revert("privateTransfer: too many memos"))?;

	// Step 5: the arrays must line up. A length mismatch is malformed input, not a
	// balance question, and the proof cannot catch it — it constrains values, not
	// how many memos were attached, so a short memo array would silently drop the
	// secrets for an output note that still gets created.
	if nullifiers.is_empty() {
		return Err(revert("privateTransfer: at least one nullifier required"));
	}
	if nullifiers.len() != commitments.len() {
		return Err(revert(
			"privateTransfer: nullifier/commitment count mismatch",
		));
	}
	if commitments.len() != encrypted_memos.len() {
		return Err(revert("privateTransfer: commitment/memo count mismatch"));
	}

	// Step 6: asset_id.
	let asset_id = abi::read_u32(params, 160)?;

	// Step 7: fee paid to the relayer.
	let fee = balance::<T>(
		abi::read_u256(params, 192)?,
		"privateTransfer: fee overflow",
		"privateTransfer: fee conversion failed",
	)?;

	// Step 8: circuit_version, selecting the VK the proof is checked against.
	let circuit_version = abi::read_u32(params, 224)?;

	Ok(pallet_shielded_pool::Call::<T>::private_transfer {
		proof,
		merkle_root,
		nullifiers,
		commitments,
		encrypted_memos,
		asset_id,
		fee,
		circuit_version,
	})
}
