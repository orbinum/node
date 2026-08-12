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
//! `relayer` is not in the ABI: it comes from `handle.context().caller`.

use alloc::vec::Vec;

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};
use frame_support::BoundedVec;
use sp_core::U256;

use crate::abi;

/// Selector for the signature in this module's header.
pub const SELECTOR: [u8; 4] = [0x4e, 0x50, 0x53, 0x48];

/// Maximum byte length of a serialised Groth16 proof accepted by the pallet.
const MAX_PROOF_LEN: u32 = 512;

/// Decodes `input` into a ready-to-dispatch `unshield` call.
///
/// Rejects anything the pallet would have to reject anyway, plus the inputs that
/// are irrecoverable rather than merely invalid: a zero amount, the zero
/// recipient, and a malformed change memo.
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

	// Step 1: require the head through `change_commitment`. The last two slots are
	// checked later — the memo offset only when a change note exists (step 9), and
	// `circuit_version` in step 11.
	if params.len() < 256 {
		return Err(err("unshield: input too short"));
	}

	// Step 2: proof — dynamic, offset at slot 0.
	let proof: BoundedVec<u8, frame_support::traits::ConstU32<MAX_PROOF_LEN>> =
		abi::decode_bytes_at_slot(params, 0)?
			.try_into()
			.map_err(|_| err("unshield: proof too long"))?;

	if proof.is_empty() {
		return Err(err("unshield: proof must be non-empty"));
	}

	// Step 3: merkle_root and the nullifier of the note being spent.
	let merkle_root: pallet_shielded_pool::Hash = abi::read_bytes32(params, 32)?;

	let nullifier = pallet_shielded_pool::Nullifier::from(abi::read_bytes32(params, 64)?);

	// Step 4: asset_id.
	let asset_id = abi::decode_u32(&params[96..128])?;

	// Step 5: amount. Zero is rejected here as well as in the pallet — it is a
	// no-op that still burns the nullifier, destroying the note it spends.
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

	// Step 6: recipient. The all-zero AccountId32 has no known private key, so
	// unshielding to it destroys the funds with no possibility of recovery.
	let recipient_bytes = abi::read_bytes32(params, 160)?;
	if recipient_bytes == [0u8; 32] {
		return Err(err("unshield: recipient must not be the zero address"));
	}
	let recipient: <T as frame_system::Config>::AccountId = recipient_bytes.into();

	// Step 7: fee paid to the relayer.
	let fee: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = U256::from_big_endian(&params[192..224])
			.try_into()
			.map_err(|_| err("unshield: fee overflow"))?;
		raw.try_into()
			.map_err(|_| err("unshield: fee conversion failed"))?
	};

	// Step 8: change_commitment. All-zero means a total unshield, which leaves no
	// change note behind.
	let change_commitment: pallet_shielded_pool::Hash = abi::read_bytes32(params, 224)?;
	let is_total_unshield = change_commitment == [0u8; 32];

	// Step 9: change_encrypted_memo — dynamic, offset at slot 256. A total
	// unshield carries no memo, so a missing or malformed offset is expected
	// there. A partial one must fail loudly: the memo is the only copy of the
	// change note's secrets, and defaulting to an empty one would leave the
	// change permanently unspendable.
	let change_encrypted_memo_bytes = if params.len() >= 288 {
		match abi::decode_bytes_at_slot(params, 256) {
			Ok(bytes) => bytes,
			Err(e) if is_total_unshield => {
				let _ = e;
				Vec::new()
			}
			Err(_) => return Err(err("unshield: malformed change_encrypted_memo offset")),
		}
	} else {
		Vec::new()
	};

	let change_encrypted_memo: pallet_shielded_pool::types::EncryptedMemo =
		if change_encrypted_memo_bytes.is_empty() {
			pallet_shielded_pool::types::EncryptedMemo::default()
		} else {
			pallet_shielded_pool::types::EncryptedMemo::new(change_encrypted_memo_bytes)
				.map_err(|_| err("unshield: invalid change_encrypted_memo"))?
		};

	// Step 10: relayer. Not an ABI field — whoever submits the EVM transaction is
	// the relayer, so the calldata cannot spoof it.
	let relayer = Some(handle.context().caller);

	// Step 11: circuit_version. Checked here rather than in the step 1 guard so
	// that calldata predating this slot reports the missing field instead of a
	// generic length error.
	if params.len() < 320 {
		return Err(err("unshield: input too short (missing circuitVersion)"));
	}
	let circuit_version = abi::decode_u32(&params[288..320])?;

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
		circuit_version,
	})
}

// ─────────────────────────────────────────────────────────────────────────────

fn err(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}
