//! Runs a decoded transfer as a `pallet_balances` call from the EVM caller.

use crate::{abi::TransferCall, revert};
use alloc::format;
use fp_evm::{ExitSucceed, PrecompileHandle, PrecompileOutput, PrecompileResult};
use frame_support::dispatch::{GetDispatchInfo, PostDispatchInfo};
use pallet_evm::{AddressMapping, GasWeightMapping};
use sp_runtime::traits::{Dispatchable, StaticLookup};

/// Storage a transfer may add: a new `System::Account` entry (key and value),
/// the same figure Frontier's balance precompiles charge.
pub const NEW_ACCOUNT_STORAGE_GROWTH: u64 = 148;

/// Dispatches `transfer_allow_death` / `transfer_keep_alive` signed by the caller.
///
/// The call's weight (as gas), proof size and storage growth are recorded BEFORE
/// it runs: charging after a successful dispatch only would make every failing
/// transfer free, an unmetered loop for a spammer.
pub(crate) fn transfer<T>(
	handle: &mut impl PrecompileHandle,
	call: TransferCall,
) -> PrecompileResult
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
	let value: <T as pallet_balances::Config>::Balance = call
		.value
		.try_into()
		.map_err(|_| revert("value does not fit the balance type"))?;
	let dest = <T as frame_system::Config>::Lookup::unlookup(T::AccountId::from(call.dest));
	let balances_call = if call.keep_alive {
		pallet_balances::Call::<T>::transfer_keep_alive { dest, value }
	} else {
		pallet_balances::Call::<T>::transfer_allow_death { dest, value }
	};
	let runtime_call = <T as frame_system::Config>::RuntimeCall::from(balances_call);

	let weight = runtime_call.get_dispatch_info().total_weight();
	handle.record_cost(T::GasWeightMapping::weight_to_gas(weight))?;
	handle.record_external_cost(
		None,
		Some(weight.proof_size()),
		Some(NEW_ACCOUNT_STORAGE_GROWTH),
	)?;

	let caller: <T as frame_system::Config>::AccountId =
		T::AddressMapping::into_account_id(handle.context().caller).into();
	match runtime_call.dispatch(Some(caller).into()) {
		Ok(_) => Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: Default::default(),
		}),
		Err(e) => Err(revert(&format!("transfer failed: {:?}", e.error))),
	}
}
