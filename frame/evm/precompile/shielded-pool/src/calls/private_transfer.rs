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
//! `relayer` is not in the ABI: it comes from `handle.context().caller`.

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};
use frame_support::BoundedVec;
use sp_core::U256;

use crate::abi;

/// Selector for the signature in this module's header.
pub const SELECTOR: [u8; 4] = [0x66, 0xed, 0x2c, 0xd4];

/// Maximum byte length of a serialised Groth16 proof accepted by the pallet.
const MAX_PROOF_LEN: u32 = 512;
/// Maximum number of input nullifiers / output commitments in a single transfer.
const MAX_NOTES: u32 = 2;

/// Decodes `input` into a ready-to-dispatch `private_transfer` call.
///
/// Beyond the ABI itself, this enforces the structural invariant the proof does
/// not cover: at least one input note, and the three arrays equal in length.
pub fn decode<T>(
	handle: &impl PrecompileHandle,
	input: &[u8],
) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	let params = &input[4..];

	// Step 1: require all eight head slots. The array offsets they carry point
	// into the tail, whose bounds each decoder validates on its own.
	if params.len() < 256 {
		return Err(err("privateTransfer: input too short"));
	}

	// Step 2: proof — dynamic, offset at slot 0.
	let proof: BoundedVec<u8, frame_support::traits::ConstU32<MAX_PROOF_LEN>> =
		abi::decode_bytes_at_slot(params, 0)?
			.try_into()
			.map_err(|_| err("privateTransfer: proof too long"))?;

	if proof.is_empty() {
		return Err(err("privateTransfer: proof must be non-empty"));
	}

	// Step 3: merkle_root the proof is verified against.
	let merkle_root: pallet_shielded_pool::Hash = abi::read_bytes32(params, 32)?;

	// Step 4: the three parallel arrays — nullifiers spent, commitments created,
	// and the memo carrying each new note's secrets.
	let nullifiers: BoundedVec<
		pallet_shielded_pool::Nullifier,
		frame_support::traits::ConstU32<MAX_NOTES>,
	> = abi::decode_bytes32_array_at_slot(params, 64)?
		.into_iter()
		.map(pallet_shielded_pool::Nullifier::from)
		.collect::<alloc::vec::Vec<_>>()
		.try_into()
		.map_err(|_| err("privateTransfer: too many nullifiers"))?;

	let commitments: BoundedVec<
		pallet_shielded_pool::Commitment,
		frame_support::traits::ConstU32<MAX_NOTES>,
	> = abi::decode_bytes32_array_at_slot(params, 96)?
		.into_iter()
		.map(pallet_shielded_pool::Commitment::from)
		.collect::<alloc::vec::Vec<_>>()
		.try_into()
		.map_err(|_| err("privateTransfer: too many commitments"))?;

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

	// Step 5: the arrays must line up. A length mismatch is malformed input, not a
	// balance question, and the proof cannot catch it — it constrains values, not
	// how many memos were attached, so a short memo array would silently drop the
	// secrets for an output note that still gets created.
	if nullifiers.is_empty() {
		return Err(err("privateTransfer: at least one nullifier required"));
	}
	if nullifiers.len() != commitments.len() {
		return Err(err("privateTransfer: nullifier/commitment count mismatch"));
	}
	if commitments.len() != encrypted_memos.len() {
		return Err(err("privateTransfer: commitment/memo count mismatch"));
	}

	// Step 6: asset_id.
	let asset_id = abi::decode_u32(&params[160..192])?;

	// Step 7: fee paid to the relayer.
	let fee: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = U256::from_big_endian(&params[192..224])
			.try_into()
			.map_err(|_| err("privateTransfer: fee overflow"))?;
		raw.try_into()
			.map_err(|_| err("privateTransfer: fee conversion failed"))?
	};

	// Step 8: relayer. Not an ABI field — whoever submits the EVM transaction is
	// the relayer, so the calldata cannot spoof it.
	let relayer = Some(handle.context().caller);

	// Step 9: circuit_version, selecting the VK the proof is checked against.
	let circuit_version = abi::decode_u32(&params[224..256])?;

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
	})
}

// ─────────────────────────────────────────────────────────────────────────────

fn err(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}
