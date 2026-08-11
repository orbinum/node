//! ABI decoding and call construction for
//! `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)`.
//!
//! ## Selector
//! `keccak256("unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)")[0..4]`
//! = `0x4e505348`
//!
//! ## ABI layout (`input[4..]`) — standard head/tail encoding
//!
//! Ten 32-byte head slots. Dynamic types (`bytes`) store an OFFSET here and
//! their real data in the tail; fixed types are inline. The `#` column matches
//! the numbered steps in [`decode`] below, so the layout and the code that
//! reads it stay in the same order.
//!
//! | #  | Slot (bytes) | Type      | Field                            |
//! |----|--------------|-----------|----------------------------------|
//! | 1  | 0..32        | `uint256` | offset → `proof`                 |
//! | 2  | 32..64       | `bytes32` | `merkle_root`                    |
//! | 3  | 64..96       | `bytes32` | `nullifier`                      |
//! | 4  | 96..128      | `uint32`  | `asset_id`                       |
//! | 5  | 128..160     | `uint256` | `amount`                         |
//! | 6  | 160..192     | `bytes32` | `recipient` (AccountId32)        |
//! | 7  | 192..224     | `uint256` | `fee`                            |
//! | 8  | 224..256     | `bytes32` | `change_commitment`              |
//! | 9  | 256..288     | `uint256` | offset → `change_encrypted_memo` |
//! | 10 | 288..320     | `uint32`  | `circuit_version`                |
//!
//! ## Field notes
//!
//! - **`recipient`** is an `AccountId32` in a `bytes32` slot: either a
//!   Substrate-native account or the one derived from an H160
//!   (`H160 ++ [0x00; 12]`).
//! - **`change_commitment`** is `[0u8; 32]` for a TOTAL unshield (nothing left
//!   over, so no change note). For a PARTIAL one it is
//!   `NoteCommitment(change_value, asset_id, change_owner_pk, change_blinding)`.
//!   This single value is what decides how the memo in step 9 is treated.
//! - **`change_encrypted_memo`** is a dynamic `bytes`: the full 180-byte memo
//!   for a partial unshield, empty for a total one.
//! - **`relayer`** is not in the ABI at all — it comes from
//!   `handle.context().caller` (step 11).
//!
//! ## Why the length gate is not a single check
//!
//! The head is 320 bytes, but the gate at step 0 only requires 256. That is
//! deliberate: slots 9 and 10 were appended by later upgrades, and each is
//! checked at the point it is read (steps 9 and 10) so the error names the
//! field that is missing rather than reporting a generic "too short".

use alloc::vec::Vec;

use fp_evm::{ExitError, PrecompileFailure, PrecompileHandle};
use frame_support::BoundedVec;
use sp_core::U256;

use crate::abi;

/// `keccak256("unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)")[0..4]`
/// The trailing `uint32` is `circuitVersion` — the circuit version the spent
/// notes were created under, so the proof is verified against that version's VK.
pub const SELECTOR: [u8; 4] = [0x4e, 0x50, 0x53, 0x48];

/// Maximum byte length of a serialised Groth16 proof accepted by the pallet.
const MAX_PROOF_LEN: u32 = 512;

/// Minimum `params` length: the eight head slots this call has always had.
/// Slots 9 and 10 came later and are checked where they are read — see the
/// module header.
const HEAD_SIZE_BASE: usize = 256;
/// Through slot 9 (`change_encrypted_memo`'s offset word).
const HEAD_SIZE_WITH_MEMO: usize = 288;
/// The full ten-slot head, through `circuit_version`.
const HEAD_SIZE_FULL: usize = 320;

/// Decodes the ABI-encoded `input` and returns a ready-to-dispatch `unshield` call.
///
/// The steps below are numbered to match the ABI table in the module header.
/// Order is not arbitrary: the cheap length gate runs first (step 0) so a
/// malformed call is rejected before any allocation, and the two
/// value-destroying inputs — a zero amount and the zero recipient — are refused
/// before anything else is built.
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
	<T as frame_system::Config>::AccountId: From<[u8; 32]>,
{
	let params = &input[4..];

	// ── 0. Head gate ─────────────────────────────────────────────────────────
	// Covers slots 1–8, the reads done unconditionally below. Slots 9 and 10 are
	// gated where they are read.
	if params.len() < HEAD_SIZE_BASE {
		return Err(err("unshield: input too short"));
	}

	// ── 1. proof (slot 0 → tail) ─────────────────────────────────────────────
	// Bounded on the way in: `MAX_PROOF_LEN` is the pallet's ceiling, so an
	// oversized proof is refused here rather than at dispatch. Empty is refused
	// separately — the ZK verifier would reject it anyway, but far later.
	let proof: BoundedVec<u8, frame_support::traits::ConstU32<MAX_PROOF_LEN>> =
		abi::decode_bytes_at_slot(params, 0)?
			.try_into()
			.map_err(|_| err("unshield: proof too long"))?;

	if proof.is_empty() {
		return Err(err("unshield: proof must be non-empty"));
	}

	// ── 2. merkle_root (slot 1, inline) ──────────────────────────────────────
	let merkle_root: pallet_shielded_pool::Hash = abi::read_bytes32(params, 32)?;

	// ── 3. nullifier (slot 2, inline) ────────────────────────────────────────
	let nullifier = pallet_shielded_pool::Nullifier::from(abi::read_bytes32(params, 64)?);

	// ── 4. asset_id (slot 3, inline) ─────────────────────────────────────────
	let asset_id = abi::decode_u32(&params[96..128])?;

	// ── 5. amount (slot 4, inline) ───────────────────────────────────────────
	// Zero is refused before anything else is built: the pallet rejects it too,
	// but failing here names the field and costs no dispatch weight. Then two
	// fallible narrowing steps — the ABI word is a `uint256` while the pallet's
	// balance is at most `u128`. `try_into` rather than `as_u128()`, which
	// panics above 2^128 on a word the caller fully controls.
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

	// ── 6. recipient (slot 5, inline) ────────────────────────────────────────
	// The all-zero AccountId32 is refused: it is a valid-looking address that
	// nobody holds the key to, so unshielding to it destroys the tokens with no
	// route to recovery. Unlike a wrong-but-real address, this one is always a
	// mistake.
	let recipient_bytes = abi::read_bytes32(params, 160)?;
	if recipient_bytes == [0u8; 32] {
		return Err(err("unshield: recipient must not be the zero address"));
	}
	let recipient: <T as frame_system::Config>::AccountId = recipient_bytes.into();

	// ── 7. fee (slot 6, inline) ──────────────────────────────────────────────
	let fee: pallet_shielded_pool::BalanceOf<T> = {
		let raw: u128 = U256::from_big_endian(&params[192..224])
			.try_into()
			.map_err(|_| err("unshield: fee overflow"))?;
		raw.try_into()
			.map_err(|_| err("unshield: fee conversion failed"))?
	};

	// ── 8. change_commitment (slot 7, inline) ────────────────────────────────
	// Zero here means TOTAL unshield — the whole note leaves the pool and there
	// is no change note. This flag decides how step 9 treats a missing memo.
	let change_commitment: pallet_shielded_pool::Hash = abi::read_bytes32(params, 224)?;
	let is_total_unshield = change_commitment == [0u8; 32];

	// ── 9. change_encrypted_memo (slot 8 → tail) ─────────────────────────────
	// Absence is only tolerated for a TOTAL unshield, which legitimately has no
	// change note. On a PARTIAL one a malformed offset must fail loudly:
	// defaulting to an empty memo would commit a change note whose owner can
	// never open it — funds locked in the tree forever.
	let change_encrypted_memo_bytes = if params.len() >= HEAD_SIZE_WITH_MEMO {
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

	// `EncryptedMemo::new` pins the pallet's exact size (180 bytes); the empty
	// default is the total-unshield case, and the chain never reads inside it.
	let change_encrypted_memo: pallet_shielded_pool::types::EncryptedMemo =
		if change_encrypted_memo_bytes.is_empty() {
			pallet_shielded_pool::types::EncryptedMemo::default()
		} else {
			pallet_shielded_pool::types::EncryptedMemo::new(change_encrypted_memo_bytes)
				.map_err(|_| err("unshield: invalid change_encrypted_memo"))?
		};

	// ── 10. circuit_version (slot 9, inline) ─────────────────────────────────
	// Appended by a later upgrade, so it gets its own gate with an error that
	// names it rather than a generic "too short".
	if params.len() < HEAD_SIZE_FULL {
		return Err(err("unshield: input too short (missing circuitVersion)"));
	}
	let circuit_version = abi::decode_u32(&params[288..320])?;

	// ── 11. relayer — from the CALLER, never from calldata ───────────────────
	// Taking this from the ABI would let anyone name a third party as the fee
	// recipient. `pallet-relayer` resolves the caller's registered Substrate
	// account from it.
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
		circuit_version,
	})
}

// ─────────────────────────────────────────────────────────────────────────────

fn err(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}
