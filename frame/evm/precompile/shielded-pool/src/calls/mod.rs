//! Per-function call decoders for the shielded-pool precompile.
//!
//! Each sub-module owns:
//! - the **ABI selector** for the corresponding Solidity function,
//! - the **`decode`** function that turns raw `input` bytes into a
//!   `pallet_shielded_pool::Call<T>`.
//!
//! The precompile router in `lib.rs` only needs to match on `SELECTOR`s and
//! forward to the appropriate `decode`, then hand the call to `dispatch`.
//!
//! Each module header documents the selector and the ABI slot layout; `decode`
//! walks that layout in numbered steps. Decoding is the trust boundary, so a
//! `decode` also rejects input that is well-formed but irrecoverable — a zero
//! amount, a burn address, a memo without which a note could never be spent —
//! rather than leaving it to the pallet.
//!
//! The helpers below are the steps several decoders share. Each takes the
//! revert messages of its caller, so every rejection still names its function.

pub mod claim_relay_fees;
pub mod commit_relay;
pub mod private_transfer;
pub mod shield;
pub mod unshield;

use fp_evm::PrecompileFailure;
use pallet_shielded_pool::{BalanceOf, Proof};
use sp_core::U256;

use crate::{abi, revert};

/// The parameters after the selector, once they hold the whole `head_len`-byte
/// head. Offsets in the head point into the tail, which each dynamic decoder
/// bounds-checks on its own.
///
/// `input` holds at least the 4-byte selector: every caller has matched on it.
fn params<'a>(
	input: &'a [u8],
	head_len: usize,
	too_short: &'static str,
) -> Result<&'a [u8], PrecompileFailure> {
	let params = &input[4..];
	if params.len() < head_len {
		return Err(revert(too_short));
	}
	Ok(params)
}

/// A `uint256` amount as the pallet's balance type: `overflow` when it does not
/// fit in a `u128`, `conversion` when it does not fit in `BalanceOf<T>`.
fn balance<T>(
	value: U256,
	overflow: &'static str,
	conversion: &'static str,
) -> Result<BalanceOf<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	BalanceOf<T>: TryFrom<u128>,
{
	let raw: u128 = value.try_into().map_err(|_| revert(overflow))?;
	raw.try_into().map_err(|_| revert(conversion))
}

/// The non-empty proof whose offset pointer lives at `slot_start`.
fn proof(
	params: &[u8],
	slot_start: usize,
	too_long: &'static str,
	empty: &'static str,
) -> Result<Proof, PrecompileFailure> {
	let proof: Proof = abi::decode_bytes_at_slot(params, slot_start)?
		.try_into()
		.map_err(|_| revert(too_long))?;
	if proof.is_empty() {
		return Err(revert(empty));
	}
	Ok(proof)
}
