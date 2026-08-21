//! Tests for relay configuration management.
//!
//! Covers:
//! - `set_min_relay_fee` — governance gating, storage update, event emission,
//!   and the `MaxMinRelayFee` ceiling that keeps a typo from bricking relaying
//! - `set_allowed_selectors` — governance gating, update, clear, overflow guard
//! - Default value wiring (`T::DefaultMinRelayFee`)

use crate::{AllowedSelectors, Error, Event, MinRelayFee, mock::*};
use frame_support::{assert_noop, assert_ok};

// ─── MinRelayFee ─────────────────────────────────────────────────────────────

#[test]
fn min_relay_fee_defaults_to_constant() {
	new_test_ext().execute_with(|| {
		assert_eq!(MinRelayFee::<Test>::get(), 1_000_000_000_000_000u128);
	});
}

#[test]
fn set_min_relay_fee_updates_storage() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::set_min_relay_fee(RuntimeOrigin::root(), 42u128));
		assert_eq!(MinRelayFee::<Test>::get(), 42u128);
	});
}

#[test]
fn set_min_relay_fee_emits_event() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::set_min_relay_fee(RuntimeOrigin::root(), 99u128));
		System::assert_last_event(Event::MinRelayFeeUpdated { new_fee: 99u128 }.into());
	});
}

#[test]
fn set_min_relay_fee_requires_manage_origin() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::set_min_relay_fee(RuntimeOrigin::signed(1), 0u128),
			frame_support::error::BadOrigin,
		);
	});
}

#[test]
fn set_min_relay_fee_allows_zero() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::set_min_relay_fee(RuntimeOrigin::root(), 0u128));
		assert_eq!(MinRelayFee::<Test>::get(), 0u128);
	});
}

// ─── AllowedSelectors ────────────────────────────────────────────────────────

#[test]
fn allowed_selectors_empty_by_default() {
	new_test_ext().execute_with(|| {
		assert!(AllowedSelectors::<Test>::get().is_empty());
	});
}

#[test]
fn set_allowed_selectors_updates_storage() {
	new_test_ext().execute_with(|| {
		let sels = vec![[0xaa, 0xbb, 0xcc, 0xdd], [0x11, 0x22, 0x33, 0x44]];
		assert_ok!(Relayer::set_allowed_selectors(
			RuntimeOrigin::root(),
			sels.clone()
		));
		assert_eq!(AllowedSelectors::<Test>::get().to_vec(), sels);
	});
}

#[test]
fn set_allowed_selectors_emits_event() {
	new_test_ext().execute_with(|| {
		let sels = vec![[0xde, 0xad, 0xbe, 0xef]];
		assert_ok!(Relayer::set_allowed_selectors(RuntimeOrigin::root(), sels));
		System::assert_last_event(Event::AllowedSelectorsUpdated { count: 1 }.into());
	});
}

#[test]
fn set_allowed_selectors_empty_clears_list() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::set_allowed_selectors(
			RuntimeOrigin::root(),
			vec![[0xaa, 0xbb, 0xcc, 0xdd]]
		));
		assert_ok!(Relayer::set_allowed_selectors(
			RuntimeOrigin::root(),
			vec![]
		));
		assert!(AllowedSelectors::<Test>::get().is_empty());
		System::assert_last_event(Event::AllowedSelectorsUpdated { count: 0 }.into());
	});
}

#[test]
fn set_allowed_selectors_rejects_too_many() {
	new_test_ext().execute_with(|| {
		// MaxAllowedSelectors = 8 in the mock
		let sels: Vec<[u8; 4]> = (0u32..9).map(|i| i.to_le_bytes()).collect();
		assert_noop!(
			Relayer::set_allowed_selectors(RuntimeOrigin::root(), sels),
			Error::<Test>::TooManySelectors,
		);
	});
}

#[test]
fn set_allowed_selectors_requires_manage_origin() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::set_allowed_selectors(RuntimeOrigin::signed(1), vec![]),
			frame_support::error::BadOrigin,
		);
	});
}

#[test]
fn set_allowed_selectors_accepts_max_capacity() {
	new_test_ext().execute_with(|| {
		// Exactly MaxAllowedSelectors (8) should succeed
		let sels: Vec<[u8; 4]> = (0u32..8).map(|i| i.to_le_bytes()).collect();
		assert_ok!(Relayer::set_allowed_selectors(
			RuntimeOrigin::root(),
			sels.clone()
		));
		assert_eq!(AllowedSelectors::<Test>::get().len(), 8);
	});
}

// ─── set_min_relay_fee upper bound ───────────────────────────────────────────

#[test]
fn the_fee_ceiling_is_accepted() {
	new_test_ext().execute_with(|| {
		let ceiling = <Test as crate::Config>::MaxMinRelayFee::get();
		assert_ok!(Relayer::set_min_relay_fee(RuntimeOrigin::root(), ceiling));
		assert_eq!(crate::MinRelayFee::<Test>::get(), ceiling);
	});
}

#[test]
fn a_fee_above_the_ceiling_is_rejected() {
	// Without the cap, governance could set u128::MAX and brick EVM relaying:
	// every shielded call would fail FeeTooLow until a runtime upgrade.
	new_test_ext().execute_with(|| {
		let ceiling = <Test as crate::Config>::MaxMinRelayFee::get();
		assert_noop!(
			Relayer::set_min_relay_fee(RuntimeOrigin::root(), ceiling + 1),
			Error::<Test>::MinRelayFeeTooHigh,
		);
		assert_noop!(
			Relayer::set_min_relay_fee(RuntimeOrigin::root(), u128::MAX),
			Error::<Test>::MinRelayFeeTooHigh,
		);
	});
}

#[test]
fn a_rejected_fee_leaves_the_previous_value_intact() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::set_min_relay_fee(RuntimeOrigin::root(), 42));
		assert_noop!(
			Relayer::set_min_relay_fee(RuntimeOrigin::root(), u128::MAX),
			Error::<Test>::MinRelayFeeTooHigh,
		);
		assert_eq!(crate::MinRelayFee::<Test>::get(), 42);
	});
}
