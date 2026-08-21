//! The three dispatch modes, one per pallet origin check. Each builds its origin
//! and defers the shared work to [`super::record_and_dispatch`].

use fp_evm::{PrecompileHandle, PrecompileResult};
use frame_support::dispatch::{GetDispatchInfo, PostDispatchInfo};
use pallet_evm::AddressMapping;
use sp_runtime::traits::Dispatchable;

use super::{record_and_dispatch, RuntimeOriginOf};

/// Dispatches `call` with the **precompile's own address** as signed origin.
///
/// Used for `shield` (payable): the EVM executor already transferred `msg.value`
/// from the caller to the precompile address, so the pallet moves those funds from
/// the precompile account to the pool without touching the caller a second time.
pub fn from_self<T>(
	handle: &mut impl PrecompileHandle,
	call: pallet_shielded_pool::Call<T>,
) -> PrecompileResult
where
	T: pallet_evm::Config + pallet_shielded_pool::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_shielded_pool::Call<T>>,
	RuntimeOriginOf<T>: From<Option<<T as frame_system::Config>::AccountId>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
{
	let address = handle.context().address;
	record_and_dispatch(handle, call, || {
		let account: <T as frame_system::Config>::AccountId =
			T::AddressMapping::into_account_id(address).into();
		RuntimeOriginOf::<T>::from(Some(account))
	})
}

/// Dispatches `call` with the **EVM caller** as signed origin.
///
/// Used for `claim_shielded_fees`: the validator calls the precompile from their
/// EVM address; their `H160` is mapped to an `AccountId` and used as the signed
/// origin so `ensure_signed` succeeds in the pallet.
pub fn from_caller<T>(
	handle: &mut impl PrecompileHandle,
	call: pallet_shielded_pool::Call<T>,
) -> PrecompileResult
where
	T: pallet_evm::Config + pallet_shielded_pool::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_shielded_pool::Call<T>>,
	RuntimeOriginOf<T>: From<Option<<T as frame_system::Config>::AccountId>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
{
	let caller = handle.context().caller;
	record_and_dispatch(handle, call, || {
		let account: <T as frame_system::Config>::AccountId =
			T::AddressMapping::into_account_id(caller).into();
		RuntimeOriginOf::<T>::from(Some(account))
	})
}

/// Dispatches `call` carrying the **EVM caller** as the relaying address.
///
/// Used for `private_transfer` and `unshield`. A ZK proof authenticates the spend
/// but says nothing about who relayed it, so the relay fee has to be attributed
/// some other way. It comes from here: the EVM executor sets `caller` from the
/// transaction signature and debited its gas, so it cannot be forged by calldata.
///
/// This is why neither call carries a `relayer` argument — an argument would be an
/// unauthenticated claim that any resubmitter could rewrite to point at itself.
pub fn relayed<T>(
	handle: &mut impl PrecompileHandle,
	call: pallet_shielded_pool::Call<T>,
) -> PrecompileResult
where
	T: pallet_evm::Config + pallet_shielded_pool::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_shielded_pool::Call<T>>,
	RuntimeOriginOf<T>: From<pallet_shielded_pool::Origin>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
{
	let caller = handle.context().caller;
	record_and_dispatch(handle, call, || {
		RuntimeOriginOf::<T>::from(pallet_shielded_pool::Origin::Relayed(caller))
	})
}
