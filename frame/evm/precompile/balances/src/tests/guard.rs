use super::{revert_reason, run, transfer_handle};
use crate::mock::{bob_account, caller_account, new_test_ext, Test};
use pallet_balances::Pallet as Balances;
use sp_core::{H160, U256};

/// Runs `handle` and checks it was refused with `reason` and moved nothing.
fn assert_refused(mut handle: crate::mock::MockHandle, reason: &str) {
	let before = Balances::<Test>::free_balance(caller_account());
	assert_eq!(revert_reason(run(&mut handle)), reason);
	assert_eq!(
		Balances::<Test>::free_balance(caller_account()),
		before,
		"caller debited"
	);
	assert_eq!(
		Balances::<Test>::free_balance(bob_account()),
		0,
		"bob credited"
	);
	assert_eq!(handle.gas_used, 0, "a refused call dispatches nothing");
}

#[test]
fn static_call_is_refused() {
	new_test_ext().execute_with(|| {
		let mut handle = transfer_handle(bob_account().into(), 1_000);
		handle.is_static = true;
		assert_refused(handle, "static calls are not allowed");
	});
}

#[test]
fn delegated_call_is_refused() {
	new_test_ext().execute_with(|| {
		// A contract delegating to the precompile: the code runs at the
		// precompile's address but in the contract's context, whose caller is
		// the user who called the contract.
		let mut handle = transfer_handle(bob_account().into(), 1_000);
		handle.code_address = H160::from_low_u64_be(2050);
		handle.context.address = H160::repeat_byte(0xC0);
		assert_refused(handle, "delegated calls are not allowed");
	});
}

#[test]
fn call_with_value_is_refused() {
	new_test_ext().execute_with(|| {
		let mut handle = transfer_handle(bob_account().into(), 1_000);
		handle.context.apparent_value = U256::from(1u8);
		assert_refused(handle, "not payable");
	});
}
