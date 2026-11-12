// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! `abort`: fails a running or finished election, clears a failed one, and is
//! refused once staking fetched a page.

use super::util::*;
use crate::{
	CurrentPhase, ElectionError, ElectionProvider, Error, Event, FailReason, Phase, tests::mock::*,
};
use frame_support::{assert_noop, assert_ok};
use sp_runtime::DispatchError;

fn running() {
	let inst = instance(&mut Rng(7), 3_000, 40, 16, Stakes::Realistic);
	set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
	assert_eq!(PagedElection::start(), Ok(()));
	poll(1);
}

fn finished() {
	running();
	let mut n = 2;
	while !matches!(PagedElection::status(), Ok(Some(_))) {
		poll(n);
		n += 1;
	}
}

#[test]
fn only_the_admin_aborts() {
	new_test_ext().execute_with(|| {
		running();
		assert_noop!(
			PagedElection::abort(RuntimeOrigin::signed(1)),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn abort_with_none_origin_is_refused() {
	new_test_ext().execute_with(|| {
		running();
		assert_noop!(
			PagedElection::abort(RuntimeOrigin::none()),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn nothing_to_abort_when_idle() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			PagedElection::abort(RuntimeOrigin::root()),
			Error::<Test>::NotOngoing
		);
	});
}

#[test]
fn aborting_a_running_election_fails_it_and_staking_drains_it() {
	new_test_ext().execute_with(|| {
		running();
		assert!(CurrentPhase::<Test>::get().is_computing());
		assert_ok!(PagedElection::abort(RuntimeOrigin::root()));
		assert_eq!(
			CurrentPhase::<Test>::get(),
			Phase::Failed(FailReason::Aborted)
		);
		assert!(events().contains(&Event::ElectionFailed {
			reason: FailReason::Aborted
		}));
		// No more work, and staking's fetches fail until page 0 clears it.
		assert_eq!(
			poll(2),
			<Test as frame_system::Config>::DbWeight::get().reads(1)
		);
		let (results, electable) = fetch_like_staking();
		assert_eq!(results.len() as u32, Pages::get());
		assert!(
			results
				.iter()
				.all(|r| *r == Err(ElectionError::Failed(FailReason::Aborted)))
		);
		assert!(electable.is_empty());
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Off);
		PagedElection::do_try_state().unwrap();
	});
}

#[test]
fn aborting_a_finished_election_withholds_its_result() {
	new_test_ext().execute_with(|| {
		finished();
		assert_ok!(PagedElection::abort(RuntimeOrigin::root()));
		assert_eq!(
			PagedElection::elect(Pages::get() - 1),
			Err(ElectionError::Failed(FailReason::Aborted))
		);
	});
}

#[test]
fn aborting_a_failed_election_clears_it() {
	new_test_ext().execute_with(|| {
		running();
		assert_ok!(PagedElection::abort(RuntimeOrigin::root()));
		assert_ok!(PagedElection::abort(RuntimeOrigin::root()));
		assert_eq!(events().last(), Some(&Event::Cleared));
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Off);
		PagedElection::do_try_state().unwrap();
		assert_eq!(PagedElection::start(), Ok(()));
	});
}

/// Staking fetched the first page: aborting would leave it the winners of that
/// page alone, so the election stays and the other pages export as usual.
#[test]
fn abort_is_refused_once_staking_fetched_a_page() {
	new_test_ext().execute_with(|| {
		finished();
		let msp = Pages::get() - 1;
		let first = PagedElection::elect(msp).expect("page exports");
		assert!(!first.is_empty());
		assert_noop!(
			PagedElection::abort(RuntimeOrigin::root()),
			Error::<Test>::AlreadyFetching
		);
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Done);
		for page in (0..msp).rev() {
			assert!(PagedElection::elect(page).is_ok(), "page {page}");
		}
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Off);
	});
}

/// Clearing a failed election mid-fetch would make `status` idle with pages
/// left, and staking would wait for them forever: it is refused, and the
/// remaining fetches clear it.
#[test]
fn clearing_a_failed_election_is_refused_once_staking_fetched_a_page() {
	new_test_ext().execute_with(|| {
		running();
		assert_ok!(PagedElection::abort(RuntimeOrigin::root()));
		let msp = Pages::get() - 1;
		assert_eq!(
			PagedElection::elect(msp),
			Err(ElectionError::Failed(FailReason::Aborted))
		);
		assert_noop!(
			PagedElection::abort(RuntimeOrigin::root()),
			Error::<Test>::AlreadyFetching
		);
		assert!(matches!(PagedElection::status(), Ok(Some(_))));
		for page in (0..msp).rev() {
			assert_eq!(
				PagedElection::elect(page),
				Err(ElectionError::Failed(FailReason::Aborted))
			);
		}
		assert_eq!(PagedElection::status(), Err(()));
		PagedElection::do_try_state().unwrap();
	});
}
