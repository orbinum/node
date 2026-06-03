//! Tests that `register_relayer` carries correct dispatch metadata.
//!
//! `register_relayer` is a `ManageOrigin`-gated call with normal weight and
//! default fee behaviour (`Pays::Yes`, `DispatchClass::Normal`).

use crate::mock::*;
use frame_support::{
	dispatch::{DispatchClass, GetDispatchInfo, Pays},
	weights::Weight,
};
use sp_core::H160;

// ─── dispatch-info helpers ───────────────────────────────────────────────────

/// Build the `register_relayer` call so we can inspect its `DispatchInfo`.
fn register_relayer_call() -> crate::Call<Test> {
	crate::Call::register_relayer {
		who: 1u64,
		evm_address: H160::zero(),
	}
}

// ─── Pays::Yes (standard governance call) ────────────────────────────────────

#[test]
fn register_relayer_pays_fee() {
	let call = register_relayer_call();
	let info = call.get_dispatch_info();
	assert_eq!(
		info.pays_fee,
		Pays::Yes,
		"register_relayer must be Pays::Yes — it is a governance/sudo extrinsic"
	);
}

// ─── DispatchClass::Normal ────────────────────────────────────────────────────

#[test]
fn register_relayer_is_normal_class() {
	let call = register_relayer_call();
	let info = call.get_dispatch_info();
	assert_eq!(
		info.class,
		DispatchClass::Normal,
		"register_relayer must be DispatchClass::Normal"
	);
}

// ─── Weight is non-zero ───────────────────────────────────────────────────────

#[test]
fn register_relayer_has_non_zero_weight() {
	let call = register_relayer_call();
	let info = call.get_dispatch_info();
	assert!(
		info.call_weight != Weight::zero(),
		"register_relayer should declare a non-zero weight"
	);
}

// ─── Duplicate-registration guards are enforced ──────────────────────────────

#[test]
fn register_relayer_rejects_duplicate_evm_address() {
	new_test_ext().execute_with(|| {
		let evm = H160::from_low_u64_be(0xBEEF);
		frame_support::assert_ok!(Relayer::register_relayer(RuntimeOrigin::root(), 1u64, evm));
		// Different account, same EVM address — must fail.
		frame_support::assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::root(), 2u64, evm),
			crate::Error::<Test>::AlreadyRegistered,
		);
	});
}

#[test]
fn register_relayer_rejects_duplicate_account() {
	new_test_ext().execute_with(|| {
		frame_support::assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::root(),
			1u64,
			H160::from_low_u64_be(0xAAAA),
		));
		// Same account, different EVM address — must fail.
		frame_support::assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::root(), 1u64, H160::from_low_u64_be(0xBBBB)),
			crate::Error::<Test>::AccountAlreadyRegistered,
		);
	});
}
