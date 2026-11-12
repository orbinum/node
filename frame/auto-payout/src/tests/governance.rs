// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Who may change the limits and pause, and which limits are accepted.

use crate::{Error, Event, Limits, Paused, PayoutLimits, tests::mock::*};
use frame_support::{assert_noop, assert_ok, traits::Hooks};
use frame_system::RawOrigin;
use sp_runtime::{DispatchError, Perbill};

fn limits(floor: u32, catch_up: u32, idle: u32) -> PayoutLimits {
	PayoutLimits {
		floor: Perbill::from_percent(floor),
		catch_up: Perbill::from_percent(catch_up),
		idle: Perbill::from_percent(idle),
	}
}

#[test]
fn defaults_pass_the_integrity_test() {
	new_test_ext().execute_with(|| {
		AutoPayout::integrity_test();
		assert_eq!(Limits::<Test>::get(), DefaultLimits::get());
	});
}

#[test]
fn only_the_admin_sets_limits() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AutoPayout::set_limits(RawOrigin::Signed(1).into(), limits(3, 5, 20)),
			DispatchError::BadOrigin
		);
		assert_ok!(AutoPayout::set_limits(
			RawOrigin::Root.into(),
			limits(3, 5, 20)
		));
		assert_eq!(Limits::<Test>::get(), limits(3, 5, 20));
		assert!(events().contains(&Event::LimitsSet {
			limits: limits(3, 5, 20)
		}));
	});
}

#[test]
fn limits_above_the_caps_are_refused() {
	new_test_ext().execute_with(|| {
		for bad in [limits(11, 11, 10), limits(2, 11, 10), limits(2, 4, 26)] {
			assert_noop!(
				AutoPayout::set_limits(RawOrigin::Root.into(), bad),
				Error::<Test>::LimitAboveCap
			);
		}
		assert_noop!(
			AutoPayout::set_limits(RawOrigin::Root.into(), limits(3, 2, 10)),
			Error::<Test>::CatchUpBelowFloor
		);
	});
}

#[test]
fn a_floor_that_cannot_fit_a_page_is_refused() {
	new_test_ext().execute_with(|| {
		let tiny = PayoutLimits {
			floor: Perbill::from_parts(1_000),
			catch_up: Perbill::from_percent(4),
			idle: Perbill::from_percent(10),
		};
		assert_noop!(
			AutoPayout::set_limits(RawOrigin::Root.into(), tiny),
			Error::<Test>::FloorBelowStep
		);
	});
}

#[test]
fn pause_and_resume() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AutoPayout::pause(RawOrigin::Signed(1).into()),
			DispatchError::BadOrigin
		);
		assert_noop!(
			AutoPayout::resume(RawOrigin::Root.into()),
			Error::<Test>::NotPaused
		);
		assert_ok!(AutoPayout::pause(RawOrigin::Root.into()));
		assert!(Paused::<Test>::get());
		assert_noop!(
			AutoPayout::pause(RawOrigin::Root.into()),
			Error::<Test>::AlreadyPaused
		);
		assert_ok!(AutoPayout::resume(RawOrigin::Root.into()));
		assert!(!Paused::<Test>::get());
		assert_eq!(events(), [Event::Paused, Event::Resumed]);
	});
}

/// A pause cannot hold an era about to leave staking's history: within the
/// expiry margin it is refused, so the watchdog's resume cannot be undone.
#[test]
fn a_pause_near_expiry_is_refused() {
	new_test_ext().execute_with(|| {
		elect(0, &[(1, 40)]);
		set_active_era(0);
		run_block(1, full());
		set_active_era(1);
		run_block(2, full());
		assert_ok!(AutoPayout::pause(RawOrigin::Root.into()));
		assert_ok!(AutoPayout::resume(RawOrigin::Root.into()));

		set_active_era(HISTORY_DEPTH - EXPIRY_MARGIN);
		run_block(3, full());
		assert_noop!(
			AutoPayout::pause(RawOrigin::Root.into()),
			Error::<Test>::ExpiryNear
		);
	});
}

/// Limits stored before a weight rise may no longer fit a step; the hooks still
/// pay one step a block, and `try_state` accepts them.
#[test]
fn try_state_accepts_a_floor_below_the_step() {
	new_test_ext().execute_with(|| {
		Limits::<Test>::put(limits(0, 0, 0));
		assert!(AutoPayout::do_try_state().is_ok());
		Limits::<Test>::put(limits(5, 1, 0));
		assert!(AutoPayout::do_try_state().is_err(), "catch_up below floor");
	});
}
