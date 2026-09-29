//! ABI decoding and call construction for `commitRelay(bytes32[])`.
//!
//! ## Selector
//! `keccak256("commitRelay(bytes32[])")[0..4]` = `0xc9b235ff`
//!
//! ## ABI layout (`input[4..]`)
//! | Slot (bytes) | Type      | Field               |
//! |--------------|-----------|---------------------|
//! | 0..32        | `uint256` | offset → `commits`  |
//!
//! ## Notes
//! Each commit is `pallet_relayer::relay_commit_hash(op_hash, relayer)`. The
//! relayer is the EVM caller, carried by the dispatch origin — it must be a
//! registered relay address.

use fp_evm::PrecompileFailure;
use frame_support::{traits::ConstU32, BoundedVec};
use pallet_shielded_pool::MAX_RELAY_COMMITS_PER_CALL;
use sp_core::H256;

use super::params;
use crate::{abi, revert};

/// Selector for the signature in this module's header.
pub const SELECTOR: [u8; 4] = [0xc9, 0xb2, 0x35, 0xff];

/// Decodes `input` into a ready-to-dispatch `commit_relay` call.
pub fn decode<T>(input: &[u8]) -> Result<pallet_shielded_pool::Call<T>, PrecompileFailure>
where
	T: pallet_shielded_pool::Config,
{
	// Step 1: require the one-slot head.
	let params = params(input, 32, "commitRelay: input too short")?;

	// Step 2: commits — dynamic, offset at slot 0. The decoder bounds the count,
	// so the conversion cannot fail.
	let commits: BoundedVec<H256, ConstU32<MAX_RELAY_COMMITS_PER_CALL>> =
		abi::decode_bytes32_array_at_slot(params, 0, MAX_RELAY_COMMITS_PER_CALL as usize)?
			.into_iter()
			.map(H256)
			.collect::<alloc::vec::Vec<_>>()
			.try_into()
			.map_err(|_| revert("commitRelay: too many commits"))?;

	if commits.is_empty() {
		return Err(revert("commitRelay: at least one commit required"));
	}

	Ok(pallet_shielded_pool::Call::<T>::commit_relay { commits })
}
