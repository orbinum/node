//! Origins: who may submit a spend, and who a relayer extrinsic acts for.

use super::evm;
use crate::{
	RawOrigin,
	mock::{RuntimeOrigin, Test, acc, new_test_ext},
	origin::{RelayCaller, ensure_relay_caller, ensure_spend_origin},
};

fn signed(n: u8) -> RuntimeOrigin {
	frame_system::RawOrigin::Signed(acc(n)).into()
}

fn relayed(byte: u8) -> RuntimeOrigin {
	RawOrigin::Relayed(evm(byte)).into()
}

// ── ensure_spend_origin ──────────────────────────────────────────────────────

#[test]
fn spends_accept_unsigned_signed_and_relayed_origins() {
	new_test_ext().execute_with(|| {
		assert!(ensure_spend_origin::<Test, _>(RuntimeOrigin::none()).is_ok());
		assert!(ensure_spend_origin::<Test, _>(signed(9)).is_ok());
		assert!(ensure_spend_origin::<Test, _>(relayed(0xAA)).is_ok());
	});
}

/// Sudo dispatches as Root; a spend submitted that way would dodge the
/// unsigned-transaction checks for no benefit.
#[test]
fn spends_refuse_root() {
	new_test_ext().execute_with(|| {
		assert!(ensure_spend_origin::<Test, _>(RuntimeOrigin::root()).is_err());
	});
}

// ── ensure_relay_caller ──────────────────────────────────────────────────────

#[test]
fn a_relayed_origin_is_its_evm_address_verbatim() {
	new_test_ext().execute_with(|| {
		assert_eq!(
			ensure_relay_caller::<Test, _>(relayed(0xAA)).unwrap(),
			RelayCaller::Evm(evm(0xAA))
		);
	});
}

#[test]
fn a_signed_origin_is_its_account_registered_or_not() {
	new_test_ext().execute_with(|| {
		assert_eq!(
			ensure_relay_caller::<Test, _>(signed(9)).unwrap(),
			RelayCaller::Signed(acc(9))
		);
	});
}

#[test]
fn relayer_calls_refuse_unsigned_and_root() {
	new_test_ext().execute_with(|| {
		assert!(ensure_relay_caller::<Test, _>(RuntimeOrigin::none()).is_err());
		assert!(ensure_relay_caller::<Test, _>(RuntimeOrigin::root()).is_err());
	});
}
