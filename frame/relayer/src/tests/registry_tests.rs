//! Tests for the EVM address ↔ AccountId registry.
//!
//! ## Account conventions (see mock.rs `MockValidators`)
//! - Accounts 1–99: **non-validators** — rejected with `NotValidator`.
//! - Accounts 100+: **validator nodes** — may register freely.
//!
//! ## Covers
//! - `register_relayer`   — only validators accepted
//! - `unregister_relayer` — cleans up registry
//! - `registered_evm_address` — reverse lookup via RelayerInterface

use crate::{Error, Event, RelayerByAccount, RelayerRegistry, mock::*, traits::RelayerInterface};
use frame_support::{assert_noop, assert_ok};

// ─── register_relayer ────────────────────────────────────────────────────────

#[test]
fn validator_can_register() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_eq!(
			RelayerRegistry::<Test>::get(addr::alice_evm()),
			Some(100u64)
		);
		assert_eq!(
			RelayerByAccount::<Test>::get(100u64),
			Some(addr::alice_evm())
		);
	});
}

#[test]
fn validator_register_emits_event() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		System::assert_last_event(
			Event::RelayerRegistered {
				evm_address: addr::alice_evm(),
				account: 100u64,
			}
			.into(),
		);
	});
}

#[test]
fn non_validator_cannot_register() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(1), addr::alice_evm()),
			Error::<Test>::NotValidator,
		);
	});
}

#[test]
fn register_relayer_requires_signed() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::none(), addr::alice_evm()),
			frame_support::error::BadOrigin,
		);
	});
}

#[test]
fn register_fails_if_evm_already_taken() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(101), addr::alice_evm()),
			Error::<Test>::AlreadyRegistered,
		);
	});
}

#[test]
fn register_fails_if_account_already_registered() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(100), addr::bob_evm()),
			Error::<Test>::AccountAlreadyRegistered,
		);
	});
}

#[test]
fn two_validators_can_register_different_evm_addresses() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(101),
			addr::bob_evm()
		));
		assert_eq!(
			RelayerRegistry::<Test>::get(addr::alice_evm()),
			Some(100u64)
		);
		assert_eq!(RelayerRegistry::<Test>::get(addr::bob_evm()), Some(101u64));
	});
}

// ─── unregister_relayer ──────────────────────────────────────────────────────

#[test]
fn unregister_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(100)));
		assert!(!RelayerRegistry::<Test>::contains_key(addr::alice_evm()));
		assert!(!RelayerByAccount::<Test>::contains_key(100u64));
	});
}

#[test]
fn unregister_emits_event() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(100)));
		System::assert_last_event(
			Event::RelayerUnregistered {
				evm_address: addr::alice_evm(),
				account: 100u64,
			}
			.into(),
		);
	});
}

#[test]
fn unregister_fails_if_not_registered() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::unregister_relayer(RuntimeOrigin::signed(100)),
			Error::<Test>::NotRegistered,
		);
	});
}

#[test]
fn unregister_requires_signed() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::unregister_relayer(RuntimeOrigin::none()),
			frame_support::error::BadOrigin,
		);
	});
}

#[test]
fn can_re_register_after_unregister() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(100)));
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_eq!(
			RelayerRegistry::<Test>::get(addr::alice_evm()),
			Some(100u64)
		);
	});
}

// ─── registered_evm_address (RelayerInterface reverse lookup) ────────────────

#[test]
fn registered_evm_address_returns_none_for_unknown_account() {
	new_test_ext().execute_with(|| {
		assert_eq!(crate::Pallet::<Test>::registered_evm_address(&100u64), None);
	});
}

#[test]
fn registered_evm_address_returns_correct_address() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_eq!(
			crate::Pallet::<Test>::registered_evm_address(&100u64),
			Some(addr::alice_evm()),
		);
	});
}

#[test]
fn registered_evm_address_returns_none_after_unregister() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(100)));
		assert_eq!(crate::Pallet::<Test>::registered_evm_address(&100u64), None);
	});
}

#[test]
fn registered_evm_address_is_account_specific() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(100),
			addr::alice_evm()
		));
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(101),
			addr::bob_evm()
		));
		assert_eq!(
			crate::Pallet::<Test>::registered_evm_address(&100u64),
			Some(addr::alice_evm()),
		);
		assert_eq!(
			crate::Pallet::<Test>::registered_evm_address(&101u64),
			Some(addr::bob_evm()),
		);
	});
}
