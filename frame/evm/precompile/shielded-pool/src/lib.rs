#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub(crate) mod abi;
pub(crate) mod calls;
pub(crate) mod dispatch;

/// The ABI selectors this precompile answers to.
///
/// Exported so the relay whitelist can be pinned against them in a test rather
/// than kept in sync by hand. A hand-kept copy drifting from this one fails
/// silently: a wrong selector still yields "unsupported selector", so the
/// rejection tests stay green while the accept path quietly stops working.
pub mod selectors {
	pub use crate::calls::claim_shielded_fees::SELECTOR as CLAIM_SHIELDED_FEES;
	pub use crate::calls::private_transfer::SELECTOR as PRIVATE_TRANSFER;
	pub use crate::calls::shield::SELECTOR as SHIELD;
	pub use crate::calls::unshield::SELECTOR as UNSHIELD;
}

use core::marker::PhantomData;

use fp_evm::{ExitError, Precompile, PrecompileFailure, PrecompileHandle, PrecompileResult};
use frame_support::dispatch::GetDispatchInfo;
use sp_runtime::traits::Dispatchable;

/// EVM precompile that bridges Solidity calls into `pallet_shielded_pool` extrinsics.
///
/// Four functions are exposed, each identified by a 4-byte ABI selector:
///
/// | Selector     | Solidity signature                                                                            |
/// |-------------|-----------------------------------------------------------------------------------------------|
/// | `0x9feb22ea` | `shield(uint32,bytes32,bytes)` — payable, amount = `msg.value`                               |
/// | `0x66ed2cd4` | `privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)`            |
/// | `0x4e505348` | `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)`         |
/// | `0x88d9deba` | `claimShieldedFees(bytes32,uint256,uint32,bytes,bytes,bytes,uint32)` — signed (validators)   |
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
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("input too short: missing selector".into()),
			});
		}

		let selector: [u8; 4] = input[0..4].try_into().unwrap();

		match selector {
			calls::shield::SELECTOR => {
				let call = calls::shield::decode::<T>(handle, &input)?;
				dispatch::from_self::<T>(handle, call)
			}
			calls::private_transfer::SELECTOR => {
				let call = calls::private_transfer::decode::<T>(handle, &input)?;
				dispatch::relayed::<T>(handle, call)
			}
			calls::unshield::SELECTOR => {
				let call = calls::unshield::decode::<T>(handle, &input)?;
				dispatch::relayed::<T>(handle, call)
			}
			calls::claim_shielded_fees::SELECTOR => {
				let call = calls::claim_shielded_fees::decode::<T>(handle, &input)?;
				dispatch::from_caller::<T>(handle, call)
			}
			_ => Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("unknown selector".into()),
			}),
		}
	}
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
