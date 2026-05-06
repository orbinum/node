//! Dispatch helpers for the shielded-pool precompile.
//!
//! Two dispatch modes mirror the two pallet extrinsic origin checks:
//!
//! - [`from_self`] — dispatches with the **precompile's own address** as signed origin.
//!   Used for `shield` (payable): the EVM executor already transferred `msg.value` from
//!   the caller to the precompile address, so the pallet moves those funds from the
//!   precompile account to the pool without touching the caller a second time.
//!
//! - [`unsigned`] — dispatches with `None` origin (`ensure_none`).
//!   Used for `private_transfer` and `unshield`, where a ZK proof authenticates the
//!   operation and no transaction signer is needed.

use alloc::format;

use fp_evm::{
	ExitError, ExitSucceed, PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileResult,
};
use frame_support::dispatch::GetDispatchInfo;
use pallet_evm::{AddressMapping, GasWeightMapping};
use sp_runtime::traits::Dispatchable;

/// Dispatches `call` with the **precompile's own address** as signed origin.
///
/// Gas cost is derived from the call's dispatch weight via [`GasWeightMapping`].
pub fn from_self<T>(
	handle: &mut impl PrecompileHandle,
	call: pallet_shielded_pool::Call<T>,
) -> PrecompileResult
where
	T: pallet_evm::Config + pallet_shielded_pool::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = frame_support::dispatch::PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_shielded_pool::Call<T>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin:
		From<Option<<T as frame_system::Config>::AccountId>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
{
	let runtime_call = <<T as frame_system::Config>::RuntimeCall as From<
		pallet_shielded_pool::Call<T>,
	>>::from(call);
	let gas_cost =
		T::GasWeightMapping::weight_to_gas(runtime_call.get_dispatch_info().total_weight());
	handle.record_cost(gas_cost)?;

	let self_account: <T as frame_system::Config>::AccountId =
		T::AddressMapping::into_account_id(handle.context().address).into();
	let origin = <<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin::from(
		Some(self_account),
	);

	dispatch(runtime_call, origin)
}

/// Dispatches `call` with `None` origin (`ensure_none`).
///
/// Gas cost is derived from the call's dispatch weight via [`GasWeightMapping`].
pub fn unsigned<T>(
	handle: &mut impl PrecompileHandle,
	call: pallet_shielded_pool::Call<T>,
) -> PrecompileResult
where
	T: pallet_evm::Config + pallet_shielded_pool::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = frame_support::dispatch::PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_shielded_pool::Call<T>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin:
		From<Option<<T as frame_system::Config>::AccountId>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
{
	let runtime_call = <<T as frame_system::Config>::RuntimeCall as From<
		pallet_shielded_pool::Call<T>,
	>>::from(call);
	let gas_cost =
		T::GasWeightMapping::weight_to_gas(runtime_call.get_dispatch_info().total_weight());
	handle.record_cost(gas_cost)?;

	let origin =
		<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin::from(None);

	dispatch(runtime_call, origin)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal
// ─────────────────────────────────────────────────────────────────────────────

fn dispatch<C>(call: C, origin: C::RuntimeOrigin) -> PrecompileResult
where
	C: Dispatchable<PostInfo = frame_support::dispatch::PostDispatchInfo>,
	C::PostInfo: core::fmt::Debug,
{
	match call.dispatch(origin) {
		Ok(_) => Ok(PrecompileOutput {
			exit_status: ExitSucceed::Stopped,
			output: Default::default(),
		}),
		Err(e) => Err(PrecompileFailure::Error {
			exit_status: ExitError::Other(format!("{e:?}").into()),
		}),
	}
}
