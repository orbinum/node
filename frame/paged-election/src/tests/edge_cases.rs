//! Requests out of turn, degenerate inputs and failures.

use super::util::*;
use crate::{
	CurrentPhase, ElectionError, ElectionProvider, Event, FailReason, Phase, tests::mock::*,
};
use frame_support::weights::WeightMeter;

fn poll_until_ready() -> u64 {
	let mut n = System::block_number();
	while !matches!(PagedElection::status(), Ok(Some(_))) {
		poll(n);
		PagedElection::do_try_state().unwrap();
		n += 1;
		assert!(n < 1_000);
	}
	n
}

#[test]
fn a_second_start_is_refused_while_one_runs() {
	new_test_ext().execute_with(|| {
		let inst = instance(&mut Rng(1), 20_000, 50, 20, Stakes::Realistic);
		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
		assert_eq!(PagedElection::start(), Ok(()));
		poll(1);
		poll(2);
		let phase = CurrentPhase::<Test>::get();
		assert!(phase.is_computing(), "{phase:?}");
		assert_eq!(PagedElection::start(), Err(ElectionError::Ongoing));
		assert_eq!(CurrentPhase::<Test>::get(), phase);
		poll_until_ready();
		assert_eq!(PagedElection::start(), Err(ElectionError::Ongoing));
		// The interrupted election still matches upstream.
		let (results, _) = fetch_like_staking();
		assert!(results.iter().all(|r| r.is_ok()));
	});
}

#[test]
fn elect_before_done_errors_and_changes_nothing() {
	new_test_ext().execute_with(|| {
		assert_eq!(PagedElection::elect(0), Err(ElectionError::NotOngoing));
		let inst = instance(&mut Rng(2), 3_000, 50, 20, Stakes::Realistic);
		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
		assert_eq!(PagedElection::start(), Ok(()));
		let mut n = 1;
		while CurrentPhase::<Test>::get().is_computing() {
			assert_eq!(PagedElection::status(), Ok(None));
			let phase = CurrentPhase::<Test>::get();
			assert_eq!(
				PagedElection::elect(Pages::get() - 1),
				Err(ElectionError::NotReady)
			);
			assert_eq!(PagedElection::elect(0), Err(ElectionError::NotReady));
			assert_eq!(CurrentPhase::<Test>::get(), phase);
			poll(n);
			n += 1;
		}
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Done);
	});
}

#[test]
fn fewer_candidates_than_seats_elects_them_all() {
	new_test_ext().execute_with(|| {
		// Candidate 3 has no approval: elected last, with no support.
		let inst = Instance {
			targets: vec![1, 2, 3],
			voters: vec![(10, 100, vec![1, 2]), (11, 50, vec![2]), (12, 7, vec![99])],
			desired: 5,
		};
		let outcome = check_parity(&inst, true);
		assert_eq!(
			outcome.winners.iter().map(|w| w.0).collect::<Vec<_>>(),
			vec![2, 1, 3]
		);
		assert!(!totals(&outcome.pages).contains_key(&3));
	});
}

#[test]
fn no_voters_elects_targets_in_order() {
	new_test_ext().execute_with(|| {
		let inst = Instance {
			targets: vec![5, 6, 7, 8],
			voters: vec![],
			desired: 2,
		};
		let outcome = check_parity(&inst, true);
		assert_eq!(
			outcome.winners.iter().map(|w| w.0).collect::<Vec<_>>(),
			vec![5, 6]
		);
		assert!(outcome.pages.iter().all(|p| p.is_empty()));
	});
}

#[test]
fn no_targets_or_no_seats_elects_nobody() {
	for (targets, desired) in [(vec![], 3), (vec![1, 2], 0)] {
		new_test_ext().execute_with(|| {
			let inst = Instance {
				targets,
				voters: vec![(10, 5, vec![1, 2])],
				desired,
			};
			let outcome = check_parity(&inst, true);
			assert!(outcome.winners.is_empty());
			assert!(
				events()
					.iter()
					.any(|e| matches!(e, Event::ElectionDone { winners: 0, .. }))
			);
		});
	}
}

#[test]
fn votes_for_non_candidates_repeats_and_empty_stakes_are_dropped() {
	let inst = Instance {
		targets: vec![1, 2, 3],
		voters: vec![
			(10, 100, vec![1, 77, 1, 2]),
			(11, 0, vec![1, 2, 3]),
			(12, 30, vec![77, 78]),
			(13, 40, vec![3, 3]),
		],
		desired: 2,
	};
	new_test_ext().execute_with(|| {
		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
		assert_eq!(PagedElection::start(), Ok(()));
		poll(1);
		let page = crate::VoterPages::<Test>::get(Pages::get() - 1).unwrap();
		let stored: Vec<_> = page.iter().map(|v| (v.who, v.votes.to_vec())).collect();
		assert_eq!(stored, vec![(10, vec![0, 1]), (13, vec![2])]);
	});
	new_test_ext().execute_with(|| {
		check_parity(&inst, true);
	});
}

/// A 1-unit candidate scores `u128::MAX` from the start; once one of its
/// voters carries a load, its score saturates as upstream's does, reported.
#[test]
fn a_tiny_approval_candidate_saturates_and_is_reported() {
	new_test_ext().execute_with(|| {
		let inst = Instance {
			targets: vec![1, 2, 3],
			voters: vec![
				(10, 1_000, vec![1]),
				(11, 1, vec![1, 2]),
				(12, 500, vec![3]),
			],
			desired: 3,
		};
		let outcome = check_parity(&inst, true);
		assert_eq!(outcome.winners.len(), 3);
		assert!(
			events()
				.iter()
				.any(|e| matches!(e, Event::ScoreSaturated { .. }))
		);
	});
}

#[test]
fn equal_scores_go_to_the_first_target() {
	new_test_ext().execute_with(|| {
		let inst = Instance {
			targets: vec![4, 3, 2, 1],
			voters: vec![
				(10, 10, vec![1]),
				(11, 10, vec![2]),
				(12, 10, vec![3]),
				(13, 10, vec![4]),
			],
			desired: 3,
		};
		let outcome = check_parity(&inst, true);
		assert_eq!(
			outcome.winners.iter().map(|w| w.0).collect::<Vec<_>>(),
			vec![4, 3, 2]
		);
	});
}

#[test]
fn repeated_targets_count_once() {
	new_test_ext().execute_with(|| {
		set_data(vec![1, 2, 1, 3], vec![(10, 10, vec![1, 3])], 2);
		assert_eq!(PagedElection::start(), Ok(()));
		poll(1);
		assert_eq!(crate::Targets::<Test>::get().to_vec(), vec![1, 2, 3]);
	});
}

fn fails_with(reason: FailReason, setup: impl FnOnce()) {
	new_test_ext().execute_with(|| {
		let inst = instance(&mut Rng(3), 500, 20, 10, Stakes::Realistic);
		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
		setup();
		assert_eq!(PagedElection::start(), Ok(()));
		poll_until_ready();
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Failed(reason));
		assert!(events().contains(&Event::ElectionFailed { reason }));
		// Staking fetches every page, gets an error each time and no winner,
		// so it keeps its validators; page 0 clears the failed election.
		let (results, electable) = fetch_like_staking();
		assert_eq!(results.len() as u32, Pages::get());
		assert!(
			results
				.iter()
				.all(|r| *r == Err(ElectionError::Failed(reason)))
		);
		assert!(electable.is_empty());
		assert_eq!(PagedElection::status(), Err(()));
		PagedElection::do_try_state().unwrap();
		assert_eq!(PagedElection::start(), Ok(()));
	});
}

#[test]
fn data_provider_failures_fail_the_election() {
	fails_with(FailReason::DataProvider, || {
		with_data(|d| d.fail_targets = true)
	});
	fails_with(FailReason::DataProvider, || {
		with_data(|d| d.fail_voters = true)
	});
	fails_with(FailReason::DataProvider, || {
		with_data(|d| d.fail_desired = true)
	});
	fails_with(FailReason::DataProvider, || {
		with_data(|d| d.targets = (1..=600).collect())
	});
}

#[test]
fn more_seats_than_winners_fails_the_election() {
	fails_with(FailReason::TooManySeats, || {
		with_data(|d| d.desired = MaxWinners::get() + 1)
	});
}

#[test]
fn start_while_failed_is_ongoing() {
	new_test_ext().execute_with(|| {
		set_data(vec![1, 2], vec![(10, 5, vec![1])], 1);
		with_data(|d| d.fail_targets = true);
		assert_eq!(PagedElection::start(), Ok(()));
		poll(1);
		assert_eq!(
			CurrentPhase::<Test>::get(),
			Phase::Failed(FailReason::DataProvider)
		);
		assert_eq!(PagedElection::start(), Err(ElectionError::Ongoing));
		assert_eq!(
			CurrentPhase::<Test>::get(),
			Phase::Failed(FailReason::DataProvider)
		);
	});
}

/// A page bigger than asked for is staking breaking its bound: the election
/// fails rather than drop the voters past it.
#[test]
fn too_many_voters_fail_the_snapshot() {
	VoterSnapshotPerBlock::set(100);
	fails_with(FailReason::DataProvider, || {
		with_data(|d| d.overfill = true)
	});
	reset_parameters();
}

/// Steps until the first winner is applied, then breaks `what`; a later round
/// step finds it and fails the election.
fn breaks_mid_rounds(what: impl FnOnce()) {
	new_test_ext().execute_with(|| {
		let inst = instance(&mut Rng(5), 500, 20, 10, Stakes::Realistic);
		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
		assert_eq!(PagedElection::start(), Ok(()));
		let mut phase = CurrentPhase::<Test>::get();
		while !matches!(phase, Phase::Apply { .. }) {
			phase = PagedElection::step(1, phase, &mut WeightMeter::new()).expect("computing");
		}
		what();
		let mut n = 1;
		while !matches!(PagedElection::status(), Ok(Some(_))) {
			poll(n);
			n += 1;
			assert!(n < 1_000);
		}
		assert_eq!(
			CurrentPhase::<Test>::get(),
			Phase::Failed(FailReason::Inconsistent)
		);
		let (results, electable) = fetch_like_staking();
		assert_eq!(results.len() as u32, Pages::get());
		assert!(electable.is_empty());
	});
}

#[test]
fn a_missing_voter_page_fails_the_rounds() {
	breaks_mid_rounds(|| {
		let page = crate::VoterPages::<Test>::iter_keys().next().unwrap();
		crate::VoterPages::<Test>::remove(page);
	});
}

#[test]
fn missing_bookkeeping_fails_the_rounds() {
	breaks_mid_rounds(crate::Meta::<Test>::kill);
}

/// Edges are capped by the stake: normalisation can only fail on scores that
/// fall back below an earlier winner's, and then the voter backs nobody.
#[test]
fn distribute_never_exceeds_the_stake() {
	use crate::phragmen::distribute;
	let stake = u64::MAX;
	let approved = [(0, 0), (1, 1), (2, 2), (3, 3)];
	let rising = [10u128, 20, 40, 80];
	let weights = distribute(stake, &approved, |r| rising[r as usize]);
	assert_eq!(weights.iter().map(|w| w.1).sum::<u128>(), u128::from(stake));
	// Two edges each worth `u128::MAX` against a tiny final load: their sum
	// overflows, so normalising fails.
	let falling = [u128::MAX, 1, u128::MAX, 1];
	let weights = distribute(stake, &approved, |r| falling[r as usize]);
	assert!(weights.is_empty(), "{weights:?}");
}
