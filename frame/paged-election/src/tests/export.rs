// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Staking fetches the pages: each holds the supports of its own voters,
//! within the bounds, and page 0 clears every trace of the election.

use super::util::*;
use crate::{
	Candidates, CurrentPhase, ElectionError, ElectionProvider, FailReason, Meta, PageInfos, Phase,
	Targets, VoterPages, Winners, tests::mock::*,
};
use frame_support::traits::Get;
use std::collections::BTreeSet;

fn finished(voters: u32, targets: u32, desired: u32) -> Instance {
	let inst = instance(&mut Rng(11), voters, targets, desired, Stakes::Realistic);
	set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
	assert_eq!(PagedElection::start(), Ok(()));
	let mut n = 1;
	while !matches!(PagedElection::status(), Ok(Some(_))) {
		poll(n);
		n += 1;
	}
	inst
}

#[test]
fn each_page_holds_its_own_voters_within_bounds() {
	VoterSnapshotPerBlock::set(200);
	new_test_ext().execute_with(|| {
		let inst = finished(1_500, 80, 30);
		let served = with_data(|d| d.served.clone());
		let mut offset = 0;
		for (page, count) in served {
			let voters: BTreeSet<_> = inst.voters[offset..offset + count]
				.iter()
				.map(|v| v.0)
				.collect();
			offset += count;
			let supports = PagedElection::elect(page).expect("page exports");
			assert!(supports.len() as u32 <= MaxWinners::get());
			for (_, support) in supports.iter() {
				assert!(
					support.voters.len() as u32
						<= <Test as crate::Config>::MaxBackersPerWinner::get()
				);
				assert!(
					support.voters.iter().all(|(v, _)| voters.contains(v)),
					"page {page}"
				);
			}
		}
		assert_eq!(offset, inst.voters.len());
	});
	reset_parameters();
}

#[test]
fn page_zero_clears_everything() {
	new_test_ext().execute_with(|| {
		finished(4_000, 40, 16);
		assert!(VoterPages::<Test>::iter_keys().count() > 1);
		for page in (1..Pages::get()).rev() {
			assert!(PagedElection::elect(page).is_ok());
			assert_eq!(CurrentPhase::<Test>::get(), Phase::Done);
		}
		assert!(PagedElection::elect(0).is_ok());

		assert_eq!(CurrentPhase::<Test>::get(), Phase::Off);
		assert!(Meta::<Test>::get().is_none());
		assert!(Targets::<Test>::get().is_empty() && Candidates::<Test>::get().is_empty());
		assert!(Winners::<Test>::get().is_empty());
		assert_eq!(VoterPages::<Test>::iter_keys().count(), 0);
		assert_eq!(PageInfos::<Test>::iter_keys().count(), 0);
		PagedElection::do_try_state().unwrap();
		assert_eq!(PagedElection::status(), Err(()));
		assert_eq!(PagedElection::elect(0), Err(ElectionError::NotOngoing));
		// The next election starts afresh.
		assert_eq!(PagedElection::start(), Ok(()));
	});
}

#[test]
fn empty_pages_export_nothing() {
	new_test_ext().execute_with(|| {
		finished(100, 10, 5);
		// 110 voters fill the most significant page only.
		assert!(!PagedElection::elect(Pages::get() - 1).unwrap().is_empty());
		for page in (0..Pages::get() - 1).rev() {
			assert_eq!(PagedElection::elect(page).map(|s| s.len()), Ok(0));
		}
	});
}

#[test]
fn a_page_beyond_the_pages_is_refused() {
	new_test_ext().execute_with(|| {
		finished(100, 10, 5);
		assert_eq!(
			PagedElection::elect(Pages::get()),
			Err(ElectionError::InvalidPage)
		);
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Done);
	});
}

#[test]
fn status_prices_a_page_fetch() {
	new_test_ext().execute_with(|| {
		assert_eq!(PagedElection::status(), Err(()));
		finished(100, 10, 5);
		assert_eq!(
			PagedElection::status(),
			Ok(Some(PagedElection::export_weight()))
		);
	});
}

#[test]
fn staking_collects_every_winner() {
	new_test_ext().execute_with(|| {
		finished(5_000, 120, 100);
		let winners: BTreeSet<_> = {
			let targets = Targets::<Test>::get();
			Winners::<Test>::get()
				.iter()
				.map(|w| targets[usize::from(w.0)])
				.collect()
		};
		let (results, electable) = fetch_like_staking();
		assert_eq!(results.len() as u32, Pages::get());
		assert!(results.iter().all(|r| r.is_ok()));
		assert_eq!(electable.into_iter().collect::<BTreeSet<_>>(), winners);
		assert_eq!(winners.len(), 100);
		assert_eq!(PagedElection::status(), Err(()));
	});
}

/// A stored page that no longer decodes errors instead of exporting as an
/// empty page; the election stays, so staking goes on with the other pages.
#[test]
fn an_undecodable_page_fails_the_export() {
	new_test_ext().execute_with(|| {
		finished(100, 10, 5);
		let msp = Pages::get() - 1;
		frame_support::storage::unhashed::put_raw(
			&VoterPages::<Test>::hashed_key_for(msp),
			&[0xff; 3],
		);
		assert_eq!(
			PagedElection::elect(msp),
			Err(ElectionError::Failed(FailReason::Inconsistent))
		);
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Done);
	});
}

#[test]
fn a_missing_page_fails_the_export() {
	new_test_ext().execute_with(|| {
		finished(100, 10, 5);
		let msp = Pages::get() - 1;
		VoterPages::<Test>::remove(msp);
		assert_eq!(
			PagedElection::elect(msp),
			Err(ElectionError::Failed(FailReason::Inconsistent))
		);
	});
}

/// Pages above `Pages` (left by an upgrade that lowered it mid-election) are
/// cleared too. Committed first: a limited clear only counts stored keys.
#[test]
fn clear_removes_pages_beyond_current_pages() {
	let mut ext = new_test_ext();
	ext.execute_with(|| {
		finished(4_000, 40, 16);
		let stale = Pages::get() + 3;
		let page = VoterPages::<Test>::iter_values().next().unwrap();
		let info = PageInfos::<Test>::iter_values().next().unwrap();
		VoterPages::<Test>::insert(stale, page);
		PageInfos::<Test>::insert(stale, info);
	});
	ext.commit_all().unwrap();
	ext.execute_with(|| {
		Pages::set(2);
		assert!(PagedElection::elect(0).is_ok());
		assert_eq!(VoterPages::<Test>::iter_keys().count(), 0);
		assert_eq!(PageInfos::<Test>::iter_keys().count(), 0);
	});
	reset_parameters();
}
