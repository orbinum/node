//! ABI decoding and call construction for
//! `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes)`.
//!
//! ## Selector
//! `keccak256("unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes)")[0..4]`
//! = `0xcc1a3b38`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field           |
//! |-------------|-----------|-----------------|
//! | 0..32       | `uint256` | offset → `proof`|
//! | 32..64      | `bytes32` | `merkle_root`   |
//! | 64..96      | `bytes32` | `nullifier`     |
//! | 96..128     | `uint32`  | `asset_id`      |
//! | 128..160    | `uint256` | `amount`        |
//! | 160..192    | `bytes32` | `recipient` (AccountId32) |
//! | 192..224    | `uint256` | `fee`           |
//! | 224..256    | `bytes32` | `change_commitment` |
//! | 256..288    | `uint256` | offset → `change_encrypted_memo` |
//!
//! `recipient` is an `AccountId32` encoded as a 32-byte ABI `bytes32` slot.
//! This can be a Substrate-native account or the `AccountId32` derived from
//! an H160 address (`H160 ++ [0x00; 12]`).
//!
//! `change_commitment` is `[0u8; 32]` for a total unshield (no change note).
//! For a partial unshield it is `NoteCommitment(change_value, asset_id, change_owner_pk, change_blinding)`.
//!
//! `change_encrypted_memo` is a dynamic `bytes` field (176 bytes for partial unshield, 0 bytes for total).
//! For a partial unshield it contains: nonce(12) || ciphertext(132) || ephPk(32).
//!
//! `relayer` is derived from `handle.context().caller` — not part of the ABI.

use alloc::vec::Vec;

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};
use frame_support::BoundedVec;
use sp_core::U256;

use crate::abi;

/// `keccak256("unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes)")[0..4]`
pub const SELECTOR: [u8; 4] = [0xcc, 0x1a, 0x3b, 0x38];

/// Maximum byte length of a serialised Groth16 proof accepted by the pallet.
const MAX_PROOF_LEN: u32 = 512;

/// Decodes the ABI-encoded `input` and returns a ready-to-dispatch `unshield` call.
///
/// `handle.context().caller` is forwarded as the `relayer` field so
/// `pallet-relayer` can route fees to the registered Substrate account.
pub fn decode<T>(
	handle: &impl PrecompileHandle,
	input: &[u8],
) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
	<T as frame_system::Config>::AccountId: From<[u8; 32]>,
{
	let params = &input[4..];
	if params.len() < 256 {
		return Err(err("unshield: input too short"));
	}

	let proof: BoundedVec<u8, frame_support::traits::ConstU32<MAX_PROOF_LEN>> =
		abi::decode_bytes_at_slot(params, 0)?
			.try_into()
			.map_err(|_| err("unshield: proof too long"))?;

	if proof.is_empty() {
		return Err(err("unshield: proof must be non-empty"));
	}

	let merkle_root: pallet_shielded_pool::Hash = abi::read_bytes32(params, 32)?;

	let nullifier = pallet_shielded_pool::Nullifier::from(abi::read_bytes32(params, 64)?);

	let asset_id = abi::decode_u32(&params[96..128])?;

	// Reject zero-amount unshield early (defense-in-depth before dispatch).
	let amount_u256 = U256::from_big_endian(&params[128..160]);
	if amount_u256.is_zero() {
		return Err(err("unshield: amount must be non-zero"));
	}
	let amount: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = amount_u256
			.try_into()
			.map_err(|_| err("unshield: amount overflow"))?;
		raw.try_into()
			.map_err(|_| err("unshield: amount conversion failed"))?
	};

	// Reject the zero AccountId32 (all-zeros): transferring to this address
	// permanently destroys tokens with no possibility of recovery.
	let recipient_bytes = abi::read_bytes32(params, 160)?;
	if recipient_bytes == [0u8; 32] {
		return Err(err("unshield: recipient must not be the zero address"));
	}
	let recipient: <T as frame_system::Config>::AccountId = recipient_bytes.into();

	let fee: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = U256::from_big_endian(&params[192..224])
			.try_into()
			.map_err(|_| err("unshield: fee overflow"))?;
		raw.try_into()
			.map_err(|_| err("unshield: fee conversion failed"))?
	};

	let change_commitment: pallet_shielded_pool::Hash = abi::read_bytes32(params, 224)?;

	// Decode change_encrypted_memo as a dynamic bytes field.
	// Offset pointer lives at slot 256 (params[256..288]).
	let change_encrypted_memo_bytes = if params.len() >= 288 {
		abi::decode_bytes_at_slot(params, 256).unwrap_or_default()
	} else {
		Vec::new()
	};

	// Convert to EncryptedMemo (max 176 bytes per pallet definition).
	// Empty bytes (total unshield) is allowed and results in an empty EncryptedMemo.
	let change_encrypted_memo: pallet_shielded_pool::types::EncryptedMemo =
		if change_encrypted_memo_bytes.is_empty() {
			// Total unshield: empty memo
			pallet_shielded_pool::types::EncryptedMemo::default()
		} else {
			// Partial unshield: create from bytes
			pallet_shielded_pool::types::EncryptedMemo::new(change_encrypted_memo_bytes)
				.map_err(|_| err("unshield: invalid change_encrypted_memo"))?
		};

	let relayer = Some(handle.context().caller);

	Ok(pallet_shielded_pool::Call::<T>::unshield {
		proof,
		merkle_root,
		nullifier,
		asset_id,
		amount,
		recipient,
		fee,
		change_commitment,
		change_encrypted_memo,
		relayer,
	})
}

// ─────────────────────────────────────────────────────────────────────────────

fn err(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}
