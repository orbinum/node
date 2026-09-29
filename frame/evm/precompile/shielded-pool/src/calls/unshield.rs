//! ABI decoding and call construction for
//! `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)`.
//!
//! ## Selector
//! `keccak256("unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)")[0..4]`
//! = `0x4e505348`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field                            |
//! |--------------|-----------|----------------------------------|
//! | 0..32        | `uint256` | offset → `proof`                 |
//! | 32..64       | `bytes32` | `merkle_root`                    |
//! | 64..96       | `bytes32` | `nullifier`                      |
//! | 96..128      | `uint32`  | `asset_id`                       |
//! | 128..160     | `uint256` | `amount`                         |
//! | 160..192     | `bytes32` | `recipient` (AccountId32)        |
//! | 192..224     | `uint256` | `fee`                            |
//! | 224..256     | `bytes32` | `change_commitment`              |
//! | 256..288     | `uint256` | offset → `change_encrypted_memo` |
//! | 288..320     | `uint32`  | `circuit_version`                |
//!
//! ## Notes
//! `recipient` is an `AccountId32` in a `bytes32` slot — either a Substrate-native
//! account or one derived from an H160 (`H160 ++ [0x00; 12]`).
//!
//! `change_commitment` is all-zero for a total unshield. For a partial one it is
//! `NoteCommitment(change_value, asset_id, change_owner_pk, change_blinding)`, and
//! `change_encrypted_memo` then holds `nonce(12) || ciphertext(132) || ephPk(32)`.
//!
//! The relay fee recipient is not in the ABI: it is the relayer that recorded a
//! relay commit for this spend (`commitRelay`), whoever submits it.

use fp_evm::PrecompileFailure;
use pallet_shielded_pool::types::EncryptedMemo;

use super::{balance, params, proof};
use crate::{abi, revert};

/// Selector for the signature in this module's header.
pub const SELECTOR: [u8; 4] = [0x4e, 0x50, 0x53, 0x48];

/// Decodes `input` into a ready-to-dispatch `unshield` call.
///
/// Rejects anything the pallet would have to reject anyway, plus the inputs that
/// are irrecoverable rather than merely invalid: a zero amount, the zero
/// recipient, and a malformed change memo.
pub fn decode<T>(input: &[u8]) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
	<T as frame_system::Config>::AccountId: From<[u8; 32]>,
{
	// Step 1: require the whole 10-slot head.
	let params = params(input, 320, "unshield: input too short")?;

	// Step 2: proof — dynamic, offset at slot 0.
	let proof = proof(
		params,
		0,
		"unshield: proof too long",
		"unshield: proof must be non-empty",
	)?;

	// Step 3: merkle_root and the nullifier of the note being spent.
	let merkle_root: pallet_shielded_pool::Hash = abi::read_bytes32(params, 32)?;
	let nullifier = pallet_shielded_pool::Nullifier::from(abi::read_bytes32(params, 64)?);

	// Step 4: asset_id.
	let asset_id = abi::read_u32(params, 96)?;

	// Step 5: amount. Zero is rejected here as well as in the pallet — it is a
	// no-op that still burns the nullifier, destroying the note it spends.
	let amount_u256 = abi::read_u256(params, 128)?;
	if amount_u256.is_zero() {
		return Err(revert("unshield: amount must be non-zero"));
	}
	let amount = balance::<T>(
		amount_u256,
		"unshield: amount overflow",
		"unshield: amount conversion failed",
	)?;

	// Step 6: recipient. The all-zero AccountId32 has no known private key, so
	// unshielding to it destroys the funds with no possibility of recovery.
	let recipient_bytes = abi::read_bytes32(params, 160)?;
	if recipient_bytes == [0u8; 32] {
		return Err(revert("unshield: recipient must not be the zero address"));
	}
	let recipient: <T as frame_system::Config>::AccountId = recipient_bytes.into();

	// Step 7: fee paid to the relayer.
	let fee = balance::<T>(
		abi::read_u256(params, 192)?,
		"unshield: fee overflow",
		"unshield: fee conversion failed",
	)?;

	// Step 8: change_commitment. All-zero means a total unshield, which leaves no
	// change note behind.
	let change_commitment: pallet_shielded_pool::Hash = abi::read_bytes32(params, 224)?;

	// Step 9: change_encrypted_memo — dynamic, offset at slot 256. Always
	// encoded: a total unshield carries an empty one. The pallet then requires
	// exactly 180 bytes when there is a change note, and none otherwise.
	let change_encrypted_memo_bytes = abi::decode_bytes_at_slot(params, 256)
		.map_err(|_| revert("unshield: malformed change_encrypted_memo"))?;
	let change_encrypted_memo = if change_encrypted_memo_bytes.is_empty() {
		EncryptedMemo::default()
	} else {
		EncryptedMemo::new(change_encrypted_memo_bytes)
			.map_err(|_| revert("unshield: invalid change_encrypted_memo"))?
	};

	// Step 10: circuit_version.
	let circuit_version = abi::read_u32(params, 288)?;

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
		circuit_version,
	})
}
