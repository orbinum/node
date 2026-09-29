//! ABI decoding and call construction for `claimRelayFees(uint32,uint256)`.
//!
//! ## Selector
//! `keccak256("claimRelayFees(uint32,uint256)")[0..4]` = `0x2a3274dd`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field      |
//! |--------------|-----------|------------|
//! | 0..32        | `uint32`  | `asset_id` |
//! | 32..64       | `uint256` | `amount`   |
//!
//! ## Notes
//! The claimant is the EVM caller, carried by the dispatch origin: it spends the
//! pending fees of the account registered to that address and receives them in
//! its own mirror account.

use fp_evm::PrecompileFailure;

use super::{balance, params};
use crate::{abi, revert};

/// Selector for the signature in this module's header.
pub const SELECTOR: [u8; 4] = [0x2a, 0x32, 0x74, 0xdd];

/// Decodes `input` into a ready-to-dispatch `claim_relay_fees` call.
pub fn decode<T>(input: &[u8]) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	// Step 1: require the two-slot head.
	let params = params(input, 64, "claimRelayFees: input too short")?;

	// Step 2: asset_id.
	let asset_id = abi::read_u32(params, 0)?;

	// Step 3: amount. A zero claim would move nothing.
	let amount_u256 = abi::read_u256(params, 32)?;
	if amount_u256.is_zero() {
		return Err(revert("claimRelayFees: amount must be non-zero"));
	}
	let amount = balance::<T>(
		amount_u256,
		"claimRelayFees: amount overflow",
		"claimRelayFees: amount conversion failed",
	)?;

	Ok(pallet_shielded_pool::Call::<T>::claim_relay_fees { asset_id, amount })
}
