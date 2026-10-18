//! # EVM Precompile — Balances
//!
//! Exposes native `pallet_balances` transfers to arbitrary `AccountId32`
//! destinations from EVM contracts and wallets.
//!
//! ## ABI selectors
//!
//! | Function                             | Selector     |
//! |--------------------------------------|--------------|
//! | `transfer(bytes32,uint256)`          | `0x6a467394` |
//! | `transferKeepAlive(bytes32,uint256)` | `0xac6ac4c4` |
//!
//! The `bytes32` is the recipient's raw `AccountId32` (an Sr25519 public key, or
//! an EVM-suffix account `[H160 | 12×0x00]`); the `uint256` is the amount and
//! must fit in `u128`. The calldata is exactly selector + the two words.
//!
//! ## Caller
//!
//! The transfer debits `msg.sender`. Static and delegated calls (DELEGATECALL,
//! CALLCODE) are refused, so a contract moves only its own balance, never its
//! caller's; calls carrying value are refused too (`guard`).
//!
//! ## Gas and failures
//!
//! The call dispatches `Balances::transfer_allow_death` / `transfer_keep_alive`
//! as the caller and is charged that call's weight, its proof size and the
//! storage a new account takes, before it runs — a failing transfer is not free
//! (`dispatch`). Every failure reverts with a Solidity `Error(string)`, so the
//! caller keeps its unused gas and tools decode the reason.
//!
//! ## Deployment address
//!
//! `hash(2050)` — precompile address `0x…0802` on Orbinum networks.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod abi;
mod dispatch;
mod guard;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use core::marker::PhantomData;

use fp_evm::{Precompile, PrecompileFailure, PrecompileHandle, PrecompileResult};
use frame_support::dispatch::{GetDispatchInfo, PostDispatchInfo};
use sp_runtime::traits::Dispatchable;

pub use abi::{SEL_TRANSFER, SEL_TRANSFER_KEEP_ALIVE};
pub use dispatch::NEW_ACCOUNT_STORAGE_GROWTH;

pub struct BalancesPrecompile<T>(PhantomData<T>);

impl<T> Precompile for BalancesPrecompile<T>
where
	T: pallet_evm::Config + pallet_balances::Config,
	T::AccountId: From<[u8; 32]>,
	<T as pallet_balances::Config>::Balance: TryFrom<u128>,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_balances::Call<T>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin:
		From<Option<<T as frame_system::Config>::AccountId>>,
{
	fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
		guard::ensure_direct_call(handle)?;
		let call = abi::decode(handle.input())?;
		dispatch::transfer::<T>(handle, call)
	}
}

/// A revert carrying `msg` as a Solidity `Error(string)`: the caller gets its
/// unused gas back and tools decode the reason.
pub(crate) fn revert(msg: &str) -> PrecompileFailure {
	precompile_utils::prelude::revert(msg)
}
