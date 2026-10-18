use super::{encode_transfer, revert_reason, run, transfer_handle};
use crate::{
	mock::{bob_account, caller_account, eve_evm_account, new_test_ext, MockHandle, Test},
	NEW_ACCOUNT_STORAGE_GROWTH, SEL_TRANSFER, SEL_TRANSFER_KEEP_ALIVE,
};
use frame_support::dispatch::GetDispatchInfo;
use pallet_balances::Pallet as Balances;
use pallet_evm::GasWeightMapping;

const START: u128 = 1_000_000;

fn free(who: &sp_runtime::AccountId32) -> u128 {
	Balances::<Test>::free_balance(who)
}

/// Gas a transfer of this kind is charged: its declared dispatch weight.
fn expected_gas(keep_alive: bool) -> u64 {
	let dest = bob_account();
	let call: crate::mock::RuntimeCall = if keep_alive {
		pallet_balances::Call::<Test>::transfer_keep_alive { dest, value: 1 }.into()
	} else {
		pallet_balances::Call::<Test>::transfer_allow_death { dest, value: 1 }.into()
	};
	<Test as pallet_evm::Config>::GasWeightMapping::weight_to_gas(
		call.get_dispatch_info().total_weight(),
	)
}

#[test]
fn transfer_moves_the_amount() {
	new_test_ext().execute_with(|| {
		let mut handle = transfer_handle(bob_account().into(), 1_000);
		assert!(run(&mut handle).is_ok());
		assert_eq!(free(&caller_account()), START - 1_000);
		assert_eq!(free(&bob_account()), 1_000);
	});
}

#[test]
fn transfer_keep_alive_moves_the_amount() {
	new_test_ext().execute_with(|| {
		let input = encode_transfer(SEL_TRANSFER_KEEP_ALIVE, bob_account().into(), 500);
		assert!(run(&mut MockHandle::new(input)).is_ok());
		assert_eq!(free(&caller_account()), START - 500);
		assert_eq!(free(&bob_account()), 500);
	});
}

#[test]
fn transfer_keep_alive_never_kills_the_sender() {
	new_test_ext().execute_with(|| {
		let input = encode_transfer(SEL_TRANSFER_KEEP_ALIVE, bob_account().into(), START);
		let reason = revert_reason(run(&mut MockHandle::new(input)));
		assert!(reason.starts_with("transfer failed:"), "{reason}");
		assert_eq!(free(&caller_account()), START);
		assert_eq!(free(&bob_account()), 0);
	});
}

#[test]
fn transfer_can_drain_the_sender() {
	new_test_ext().execute_with(|| {
		assert!(run(&mut transfer_handle(bob_account().into(), START)).is_ok());
		assert_eq!(free(&caller_account()), 0);
		assert_eq!(free(&bob_account()), START);
	});
}

#[test]
fn any_account_id32_can_receive() {
	new_test_ext().execute_with(|| {
		for dest in [
			eve_evm_account(),
			sp_runtime::AccountId32::from([0x77u8; 32]),
		] {
			assert!(run(&mut transfer_handle(dest.clone().into(), 100)).is_ok());
			assert_eq!(free(&dest), 100);
		}
	});
}

#[test]
fn insufficient_balance_reverts_with_the_pallet_error() {
	new_test_ext().execute_with(|| {
		let reason = revert_reason(run(&mut transfer_handle(bob_account().into(), START + 1)));
		assert!(reason.starts_with("transfer failed:"), "{reason}");
		assert_eq!(free(&caller_account()), START);
		assert_eq!(free(&bob_account()), 0);
	});
}

#[test]
fn the_dispatch_weight_is_charged_up_front() {
	new_test_ext().execute_with(|| {
		for (selector, keep_alive) in [(SEL_TRANSFER, false), (SEL_TRANSFER_KEEP_ALIVE, true)] {
			let mut handle = MockHandle::new(encode_transfer(selector, bob_account().into(), 10));
			assert!(run(&mut handle).is_ok());
			assert!(expected_gas(keep_alive) > 0);
			assert_eq!(handle.gas_used, expected_gas(keep_alive));
			assert!(handle.proof_size > 0, "proof size is metered");
			assert_eq!(handle.storage_growth, NEW_ACCOUNT_STORAGE_GROWTH);
		}
	});
}

#[test]
fn a_failing_transfer_is_still_charged() {
	new_test_ext().execute_with(|| {
		// Charging only after a successful dispatch would make failures free.
		let mut handle = transfer_handle(bob_account().into(), START + 1);
		assert!(run(&mut handle).is_err());
		assert_eq!(handle.gas_used, expected_gas(false));
	});
}
