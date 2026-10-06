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

/// The ABI selectors this precompile answers to.
///
/// Exported so the relay whitelist can be pinned against them in a test rather
/// than kept in sync by hand. A hand-kept copy drifting from this one fails
/// silently: a wrong selector still yields "unknown selector", so the
/// rejection tests stay green while the accept path quietly stops working.
pub mod selectors {
	pub use crate::calls::claim_relay_fees::SELECTOR as CLAIM_RELAY_FEES;
	pub use crate::calls::commit_relay::SELECTOR as COMMIT_RELAY;
	pub use crate::calls::private_transfer::SELECTOR as PRIVATE_TRANSFER;
	pub use crate::calls::shield::SELECTOR as SHIELD;
	pub use crate::calls::unshield::SELECTOR as UNSHIELD;
}

/// Most commits one `commitRelay` call carries.
pub use pallet_shielded_pool::MAX_RELAY_COMMITS_PER_CALL;

/// Most notes one spend consumes.
pub use calls::private_transfer::MAX_NOTES as MAX_SPEND_INPUTS;

/// EVM precompile that bridges Solidity calls into `pallet_shielded_pool` extrinsics.
///
/// Five functions are exposed, each identified by a 4-byte ABI selector:
///
/// | Selector     | Solidity signature                                                                    |
/// |--------------|---------------------------------------------------------------------------------------|
/// | `0xf25897e0` | `shield(uint32,bytes32,bytes,bytes,uint32)` — payable, amount = `msg.value`           |
/// | `0x66ed2cd4` | `privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)`    |
/// | `0x4e505348` | `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)` |
/// | `0xc9b235ff` | `commitRelay(bytes32[])` — registered relayers                                        |
/// | `0x2a3274dd` | `claimRelayFees(uint32,uint256)` — registered relayers                                |
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
		From<Option<<T as frame_system::Config>::AccountId>> + From<pallet_shielded_pool::Origin>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
	<T as frame_system::Config>::AccountId: From<[u8; 32]>,
{
	fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
		let input = handle.input().to_vec();

		if input.len() < 4 {
			return Err(revert("input too short: missing selector"));
		}

		// Every call acts for the account that called the precompile. Under
		// DELEGATECALL `caller` is the delegating contract's caller — any contract
		// a relayer calls could spend its commit quota or claim in its name — and
		// under STATICCALL nothing may change state. Refuse both.
		if handle.is_static() || handle.code_address() != handle.context().address {
			return Err(revert("static or delegated calls are not allowed"));
		}

		let selector: [u8; 4] = input[0..4].try_into().unwrap();

		match selector {
			calls::shield::SELECTOR => {
				let call = calls::shield::decode::<T>(handle, &input)?;
				dispatch::from_self::<T>(handle, call)
			}
			calls::private_transfer::SELECTOR => {
				let call = calls::private_transfer::decode::<T>(&input)?;
				dispatch::relayed::<T>(handle, call)
			}
			calls::unshield::SELECTOR => {
				let call = calls::unshield::decode::<T>(&input)?;
				dispatch::relayed::<T>(handle, call)
			}
			calls::commit_relay::SELECTOR => {
				let call = calls::commit_relay::decode::<T>(&input)?;
				dispatch::relayed::<T>(handle, call)
			}
			calls::claim_relay_fees::SELECTOR => {
				let call = calls::claim_relay_fees::decode::<T>(&input)?;
				dispatch::relayed::<T>(handle, call)
			}
			// A revert, not an error: an unknown selector must not burn the caller's
			// gas limit.
			_ => Err(revert("unknown selector")),
		}
	}
}

/// Decodes the calldata of a relayable spend (`unshield` / `privateTransfer`)
/// exactly as `execute` does; `None` for anything else or malformed input.
///
/// Lets the runtime derive the relay commit for calldata a node is about to
/// relay from the same decoder the precompile will run on it.
pub fn decode_relayable_call<T>(input: &[u8]) -> Option<pallet_shielded_pool::Call<T>>
where
	T: pallet_shielded_pool::Config,
	pallet_shielded_pool::BalanceOf<T>: TryFrom<u128>,
	<T as frame_system::Config>::AccountId: From<[u8; 32]>,
{
	let selector: [u8; 4] = input.get(0..4)?.try_into().ok()?;
	match selector {
		calls::unshield::SELECTOR => calls::unshield::decode::<T>(input).ok(),
		calls::private_transfer::SELECTOR => calls::private_transfer::decode::<T>(input).ok(),
		_ => None,
	}
}

/// A revert carrying `msg` as a Solidity `Error(string)`: the caller gets its
/// unused gas back and tools decode the reason. An `Error` exit would burn the
/// whole gas limit, so a relayer submitting a spend that fails (already spent,
/// say) would pay for all of it. Every failure of this precompile goes through
/// here, from a malformed selector to a pallet error.
pub(crate) fn revert(msg: &str) -> PrecompileFailure {
	precompile_utils::prelude::revert(msg)
}
