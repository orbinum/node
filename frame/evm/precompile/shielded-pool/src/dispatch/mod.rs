//! Dispatch helpers for the shielded-pool precompile.
//!
//! Three dispatch modes mirror the pallet's extrinsic origin checks. They differ
//! only in the origin they build; everything else — converting the pallet call to
//! a runtime call, charging gas from its weight, mapping the dispatch result to a
//! precompile outcome — is shared here and reached through [`record_and_dispatch`].
//!
//! - [`origin::from_self`] — the precompile's own address as signed origin.
//! - [`origin::from_caller`] — the EVM caller's mapped address as signed origin.
//! - [`origin::relayed`] — carries the EVM caller as the relaying address.

mod origin;

pub use origin::{from_caller, from_self, relayed};

use alloc::format;

use fp_evm::{
	ExitError, ExitSucceed, PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileResult,
};
use frame_support::dispatch::{GetDispatchInfo, PostDispatchInfo};
use pallet_evm::GasWeightMapping;
use sp_runtime::traits::Dispatchable;

/// The runtime origin type for `T`'s runtime call.
type RuntimeOriginOf<T> = <<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin;

/// Converts the pallet call to a runtime call, charges its gas, dispatches it with
/// the origin from `build_origin`, and maps the result to a precompile outcome. Each
/// mode in [`origin`] just builds its origin and hands it here — the rest is shared.
fn record_and_dispatch<T>(
	handle: &mut impl PrecompileHandle,
	call: pallet_shielded_pool::Call<T>,
	build_origin: impl FnOnce() -> RuntimeOriginOf<T>,
) -> PrecompileResult
where
	T: pallet_evm::Config + pallet_shielded_pool::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_shielded_pool::Call<T>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
{
	let runtime_call = <<T as frame_system::Config>::RuntimeCall as From<
		pallet_shielded_pool::Call<T>,
	>>::from(call);
	let gas_cost =
		T::GasWeightMapping::weight_to_gas(runtime_call.get_dispatch_info().total_weight());
	handle.record_cost(gas_cost)?;

	dispatch(runtime_call, build_origin())
}

/// Dispatches an already-built runtime call and maps its result.
fn dispatch<C>(call: C, origin: C::RuntimeOrigin) -> PrecompileResult
where
	C: Dispatchable<PostInfo = PostDispatchInfo>,
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
