//! Dispatch helpers for the shielded-pool precompile.
//!
//! [`origin::from_self`] builds the origin (the precompile's own address,
//! signed); converting the pallet call to a runtime call, charging gas from its
//! weight and mapping the dispatch result to a precompile outcome live here, in
//! [`record_and_dispatch`].

mod origin;

pub use origin::from_self;

use alloc::format;

use fp_evm::{ExitSucceed, PrecompileHandle, PrecompileOutput, PrecompileResult};
use frame_support::dispatch::{GetDispatchInfo, PostDispatchInfo};
use pallet_evm::GasWeightMapping;
use sp_runtime::traits::Dispatchable;

use crate::revert;

/// The runtime origin type for `T`'s runtime call.
type RuntimeOriginOf<T> = <<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin;

/// Converts the pallet call to a runtime call, charges its gas, dispatches it with
/// the origin from `build_origin`, and maps the result to a precompile outcome.
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
		Err(e) => Err(revert(&format!("{e:?}"))),
	}
}
