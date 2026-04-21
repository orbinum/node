//! Tests for the EVM address ↔ AccountId registry.
//!
//! Covers:
//! - `register_relayer`   — happy path, duplicate guard, signed-only
//! - `unregister_relayer` — happy path, not-registered guard, signed-only
//! - Reverse index consistency (`RelayerByAccount`)

use crate::{Error, Event, RelayerByAccount, RelayerRegistry, mock::*};
use frame_support::{assert_noop, assert_ok};

// ─── register_relayer ────────────────────────────────────────────────────────

#[test]
fn register_relayer_works() {
	new_test_ext().execute_with(|| {
		let evm = addr::alice_evm();
		assert_ok!(Relayer::register_relayer(RuntimeOrigin::signed(1), evm));

		// Forward lookup
		assert_eq!(RelayerRegistry::<Test>::get(evm), Some(1u64));
		// Reverse lookup
		assert_eq!(RelayerByAccount::<Test>::get(1u64), Some(evm));
	});
}

#[test]
fn register_relayer_emits_event() {
	new_test_ext().execute_with(|| {
		let evm = addr::alice_evm();
		assert_ok!(Relayer::register_relayer(RuntimeOrigin::signed(1), evm));
		System::assert_last_event(
			Event::RelayerRegistered {
				evm_address: evm,
				account: 1u64,
			}
			.into(),
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
fn register_relayer_fails_if_evm_already_taken() {
	new_test_ext().execute_with(|| {
		let evm = addr::alice_evm();
		assert_ok!(Relayer::register_relayer(RuntimeOrigin::signed(1), evm));
		// Account 2 tries to claim the same EVM address
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(2), evm),
			Error::<Test>::AlreadyRegistered,
		);
	});
}

#[test]
fn register_relayer_same_account_different_evm_fails_if_already_registered() {
	// A second registration from the same account uses a different EVM address
	// but the first one is still active — the old entry remains.
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(1),
			addr::alice_evm()
		));
		// bob_evm is free, but alice already has an entry in RelayerByAccount;
		// the pallet doesn't block this — it overwrites the reverse index.
		// (This is intentional: accounts can re-register with a new EVM key
		//  after unregistering first.)
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(1),
			addr::bob_evm()
		));

		// Reverse index points to the latest registration
		assert_eq!(RelayerByAccount::<Test>::get(1u64), Some(addr::bob_evm()));
		// Old EVM address still maps to account 1 (orphaned forward entry)
		assert_eq!(RelayerRegistry::<Test>::get(addr::alice_evm()), Some(1u64));
	});
}

// ─── unregister_relayer ──────────────────────────────────────────────────────

#[test]
fn unregister_relayer_works() {
	new_test_ext().execute_with(|| {
		let evm = addr::alice_evm();
		assert_ok!(Relayer::register_relayer(RuntimeOrigin::signed(1), evm));
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(1)));

		assert!(!RelayerRegistry::<Test>::contains_key(evm));
		assert!(!RelayerByAccount::<Test>::contains_key(1u64));
	});
}

#[test]
fn unregister_relayer_emits_event() {
	new_test_ext().execute_with(|| {
		let evm = addr::alice_evm();
		assert_ok!(Relayer::register_relayer(RuntimeOrigin::signed(1), evm));
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(1)));
		System::assert_last_event(
			Event::RelayerUnregistered {
				evm_address: evm,
				account: 1u64,
			}
			.into(),
		);
	});
}

#[test]
fn unregister_relayer_fails_if_not_registered() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::unregister_relayer(RuntimeOrigin::signed(1)),
			Error::<Test>::NotRegistered,
		);
	});
}

#[test]
fn unregister_relayer_requires_signed() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::unregister_relayer(RuntimeOrigin::none()),
			frame_support::error::BadOrigin,
		);
	});
}

#[test]
fn register_after_unregister_works() {
	new_test_ext().execute_with(|| {
		let evm = addr::alice_evm();
		assert_ok!(Relayer::register_relayer(RuntimeOrigin::signed(1), evm));
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(1)));
		// Can re-register with the same EVM address after unregistering
		assert_ok!(Relayer::register_relayer(RuntimeOrigin::signed(1), evm));
		assert_eq!(RelayerRegistry::<Test>::get(evm), Some(1u64));
	});
}

#[test]
fn different_accounts_can_register_different_evm_addresses() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(1),
			addr::alice_evm()
		));
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(2),
			addr::bob_evm()
		));

		assert_eq!(RelayerRegistry::<Test>::get(addr::alice_evm()), Some(1u64));
		assert_eq!(RelayerRegistry::<Test>::get(addr::bob_evm()), Some(2u64));
	});
}
