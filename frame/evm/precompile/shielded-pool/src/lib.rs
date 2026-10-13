#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub(crate) mod abi;
pub(crate) mod calls;
pub(crate) mod dispatch;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use core::marker::PhantomData;

use fp_evm::{Precompile, PrecompileFailure, PrecompileHandle, PrecompileResult};
use frame_support::dispatch::GetDispatchInfo;
use sp_runtime::traits::Dispatchable;

/// Selectors of the spend and relay-fee functions retired in spec 19. Spends are
/// submitted unsigned through Substrate and fees are claimed there; calldata for
/// these reverts with [`RETIRED`].
const RETIRED_SELECTORS: [[u8; 4]; 4] = [
	[0x63, 0xd0, 0xb9, 0xa0], // privateTransfer
	[0x4e, 0x50, 0x53, 0x48], // unshield
	[0xc9, 0xb2, 0x35, 0xff], // commitRelay
	[0x2a, 0x32, 0x74, 0xdd], // claimRelayFees
];

/// Revert reason for a retired selector.
const RETIRED: &str = "retired in spec 19: submit spends unsigned via Substrate";

/// EVM precompile that bridges Solidity calls into `pallet_shielded_pool` extrinsics.
///
/// One function is exposed:
///
/// | Selector     | Solidity signature                                                          |
/// |--------------|-----------------------------------------------------------------------------|
/// | `0xf25897e0` | `shield(uint32,bytes32,bytes,bytes,uint32)` — payable, amount = `msg.value` |
///
/// `privateTransfer`, `unshield`, `commitRelay` and `claimRelayFees` are retired
/// and revert: spends are unsigned Substrate extrinsics.
///
/// Selector computation: `bytes4(keccak256("functionName(argTypes)"))`.
/// Verify with: `node -e "const {ethers}=require('ethers'); console.log(ethers.id('sig').slice(0,10))"`
pub struct ShieldedPoolPrecompile<T>(PhantomData<T>);

impl<T> Precompile for ShieldedPoolPrecompile<T>
where
	T: pallet_evm::Config + pallet_shielded_pool::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = frame_support::dispatch::PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_shielded_pool::Call<T>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin:
		From<Option<<T as frame_system::Config>::AccountId>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
{
	fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
		let input = handle.input().to_vec();

		if input.len() < 4 {
			return Err(revert("input too short: missing selector"));
		}

		// `shield` moves the value sent to this precompile's own address. Under
		// DELEGATECALL that address is the delegating contract's, and under
		// STATICCALL nothing may change state. Refuse both.
		if handle.is_static() || handle.code_address() != handle.context().address {
			return Err(revert("static or delegated calls are not allowed"));
		}

		let selector: [u8; 4] = input[0..4].try_into().unwrap();

		match selector {
			calls::shield::SELECTOR => {
				let call = calls::shield::decode::<T>(handle, &input)?;
				dispatch::from_self::<T>(handle, call)
			}
			_ if RETIRED_SELECTORS.contains(&selector) => Err(revert(RETIRED)),
			// A revert, not an error: an unknown selector must not burn the caller's
			// gas limit.
			_ => Err(revert("unknown selector")),
		}
	}
}

/// A revert carrying `msg` as a Solidity `Error(string)`: the caller gets its
/// unused gas back and tools decode the reason. An `Error` exit would burn the
/// whole gas limit, so a caller whose shield fails would pay for all of it.
/// Every failure of this precompile goes through here, from a malformed selector
/// to a pallet error.
pub(crate) fn revert(msg: &str) -> PrecompileFailure {
	precompile_utils::prelude::revert(msg)
}
