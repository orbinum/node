//! Paying eras: on a quiet chain, on a full one, behind schedule, with pages
//! claimed or refused, and within budget every block.

use crate::{Current, Event, Limits, Queue, tests::mock::*};
use frame_support::weights::Weight;
use std::collections::BTreeSet;

/// Starts era 0 with `validators` and closes it.
fn close_era_zero(validators: &[(AccountId, u32)]) {
	elect(0, validators);
	set_active_era(0);
	run_block(1, full());
	set_active_era(1);
}

/// Runs blocks from `from` until `era` is paid, at most `max` of them, with
/// `idle` left for `on_idle` in each. Checks every hook stays within its share.
fn pay_until_settled(era: u32, from: u64, max: u64, idle: Weight) -> u64 {
	let limits = Limits::<Test>::get();
	let block = Weight::from_parts(MAX_BLOCK, u64::MAX);
	for n in from..from + max {
		let (init, spent) = run_block(n, idle);
		assert!(
			init.ref_time() <= (limits.catch_up * block).ref_time(),
			"on_initialize over its share at {n}: {init:?}"
		);
		assert!(spent.all_lte(idle), "on_idle over what was left at {n}");
		assert!(
			spent.ref_time() <= (limits.idle * block).ref_time(),
			"on_idle over its share at {n}"
		);
		if era_settled(era) && Current::<Test>::get().is_none() {
			return n - from + 1;
		}
	}
	panic!("era {era} not paid within {max} blocks");
}

/// Runs only `on_idle` at block `n`, as if `on_initialize` had nothing to do.
fn idle_only(n: u64, left: Weight) -> Weight {
	System::set_block_number(n);
	// Notes the closed era without paying: the era change is `on_initialize`'s.
	AutoPayout::pause(frame_system::RawOrigin::Root.into()).ok();
	run_block(n, full());
	AutoPayout::resume(frame_system::RawOrigin::Root.into()).ok();
	let used = <AutoPayout as frame_support::traits::Hooks<u64>>::on_idle(n, left);
	AutoPayout::do_try_state().expect("invariants hold");
	used
}

fn nominators(count: u32) -> Vec<(AccountId, u32)> {
	(1..=8).map(|v| (v, count)).collect()
}

#[test]
fn a_quiet_chain_pays_from_idle_weight_only() {
	new_test_ext().execute_with(|| {
		close_era_zero(&nominators(40));
		let blocks = pay_until_settled(0, 2, WINDOW, quiet());
		// 80 pages of ~0.9 % with 10 % per block: about nine pages a block.
		assert!(blocks <= 12, "took {blocks} blocks");
		assert!(
			!events()
				.iter()
				.any(|e| matches!(e, Event::BehindSchedule { .. }))
		);
		assert!(events().contains(&Event::EraPaid {
			era: 0,
			blocks: blocks - 1
		}));
	});
}

#[test]
fn on_schedule_on_initialize_pays_nothing() {
	new_test_ext().execute_with(|| {
		close_era_zero(&nominators(40));
		run_block(2, quiet());
		let before = paid().len();
		System::set_block_number(3);
		<AutoPayout as frame_support::traits::Hooks<u64>>::on_initialize(3);
		assert_eq!(
			paid().len(),
			before,
			"ahead of schedule: no guaranteed share"
		);
	});
}

#[test]
fn a_full_chain_is_paid_by_the_floor_within_the_window() {
	new_test_ext().execute_with(|| {
		close_era_zero(&nominators(40));
		let blocks = pay_until_settled(0, 2, WINDOW, full());
		assert!(blocks <= WINDOW, "took {blocks} blocks");
		let behind: Vec<_> = events()
			.into_iter()
			.filter(|e| matches!(e, Event::BehindSchedule { .. }))
			.collect();
		assert_eq!(behind, [Event::BehindSchedule { era: 0 }], "reported once");
	});
}

#[test]
fn heavy_blocks_pay_nothing() {
	new_test_ext().execute_with(|| {
		close_era_zero(&nominators(40));
		run_block(2, full());
		run_block(3, full());
		for n in 4..20 {
			set_heavy(n);
		}
		let before = paid().len();
		for n in 4..12 {
			run_block(n, full());
		}
		assert_eq!(paid().len(), before, "heavy and full: nothing paid");
		for n in 12..20 {
			run_block(n, quiet());
		}
		assert_eq!(paid().len(), before, "heavy and quiet: nothing paid");
		let after = pay_until_settled(0, 20, WINDOW, full());
		assert!(after > 0);
	});
}

#[test]
fn every_page_is_paid_exactly_once_in_order() {
	new_test_ext().execute_with(|| {
		close_era_zero(&[(1, 9), (2, 0), (3, 4)]);
		pay_until_settled(0, 2, WINDOW, quiet());
		assert_eq!(
			paid(),
			[(0, 1, 0), (0, 1, 1), (0, 1, 2), (0, 2, 0), (0, 3, 0)],
			"pages of each validator in turn"
		);
	});
}

#[test]
fn pages_claimed_by_hand_are_skipped_silently() {
	new_test_ext().execute_with(|| {
		close_era_zero(&[(1, 8), (2, 4)]);
		claim(0, 1, 1);
		pay_until_settled(0, 2, WINDOW, quiet());
		assert_eq!(paid(), [(0, 1, 0), (0, 2, 0)]);
		assert!(
			!events()
				.iter()
				.any(|e| matches!(e, Event::PayoutSkipped { .. }))
		);
	});
}

#[test]
fn refused_pages_are_skipped_and_reported() {
	new_test_ext().execute_with(|| {
		close_era_zero(&[(1, 8), (2, 4)]);
		refuse(0, 1, 0);
		pay_until_settled(0, 2, WINDOW, quiet());
		assert_eq!(paid(), [(0, 1, 1), (0, 2, 0)]);
		assert!(events().iter().any(|e| matches!(
			e,
			Event::PayoutSkipped {
				era: 0,
				validator: 1,
				page: 0,
				..
			}
		)));
	});
}

#[test]
fn a_validator_staking_no_longer_pays_is_skipped_whole_with_one_event() {
	new_test_ext().execute_with(|| {
		// Validator 1 has five pages; staking refuses all of them.
		close_era_zero(&[(1, 5 * PAGE_SIZE), (2, 4)]);
		refuse_validator(0, 1);
		for n in 2..2 + WINDOW {
			run_block(n, quiet());
			if Current::<Test>::get().is_none() && Queue::<Test>::get().is_empty() {
				break;
			}
		}
		assert_eq!(paid(), [(0, 2, 0)]);
		// One refused call, not five.
		assert_eq!(pay_calls(), 2);
		let skipped: Vec<_> = events()
			.into_iter()
			.filter(|e| matches!(e, Event::PayoutSkipped { .. }))
			.collect();
		assert_eq!(skipped.len(), 1);
		assert!(matches!(
			skipped[0],
			Event::PayoutSkipped {
				era: 0,
				validator: 1,
				page: 0,
				..
			}
		));
		assert!(
			events()
				.iter()
				.any(|e| matches!(e, Event::EraPaid { era: 0, .. }))
		);
	});
}

#[test]
fn an_era_staking_no_longer_pays_is_dropped_and_the_next_one_paid() {
	new_test_ext().execute_with(|| {
		elect(0, &nominators(20));
		elect(1, &[(1, 4)]);
		set_active_era(0);
		run_block(1, full());
		set_active_era(2);
		refuse_era(0);
		for n in 2..2 + WINDOW {
			run_block(n, quiet());
			if Current::<Test>::get().is_none() && Queue::<Test>::get().is_empty() {
				break;
			}
		}
		// One refused call drops era 0; era 1 is paid in full.
		assert_eq!(paid(), [(1, 1, 0)]);
		assert_eq!(pay_calls(), 2);
		assert!(
			events()
				.iter()
				.any(|e| matches!(e, Event::EraExpired { era: 0 }))
		);
		assert!(
			!events()
				.iter()
				.any(|e| matches!(e, Event::PayoutSkipped { .. }))
		);
		assert!(
			events()
				.iter()
				.any(|e| matches!(e, Event::EraPaid { era: 1, .. }))
		);
	});
}

#[test]
fn a_filtered_call_waits_without_skipping_and_resumes() {
	new_test_ext().execute_with(|| {
		close_era_zero(&[(1, 8), (2, 4)]);
		set_blocked(true);
		for n in 2..12 {
			run_block(n, quiet());
		}
		// Nothing paid or skipped, one attempt per hook, the era still on its first page.
		assert!(paid().is_empty());
		assert!(pay_calls() <= 20);
		assert!(
			!events()
				.iter()
				.any(|e| matches!(e, Event::PayoutSkipped { .. }))
		);
		let state = Current::<Test>::get().expect("the era waits");
		assert_eq!((state.validator, state.page, state.done), (0, 0, 0));
		set_blocked(false);
		pay_until_settled(0, 12, WINDOW, quiet());
		assert_eq!(paid(), [(0, 1, 0), (0, 1, 1), (0, 2, 0)]);
	});
}

#[test]
fn several_eras_waiting_are_paid_oldest_first_with_the_catch_up_share() {
	new_test_ext().execute_with(|| {
		elect(0, &nominators(20));
		elect(1, &nominators(20));
		elect(2, &nominators(20));
		set_active_era(0);
		run_block(1, full());
		set_active_era(3);
		pay_until_settled(2, 2, 3 * WINDOW, full());
		assert!(era_settled(0) && era_settled(1));
		let order: Vec<_> = paid().iter().map(|(era, ..)| *era).collect();
		assert!(order.windows(2).all(|w| w[0] <= w[1]), "oldest era first");
		assert!(Queue::<Test>::get().is_empty());
	});
}

#[test]
fn an_era_without_validators_is_paid_at_once() {
	new_test_ext().execute_with(|| {
		close_era_zero(&[]);
		run_block(2, quiet());
		assert!(events().contains(&Event::EraStarted {
			era: 0,
			validators: 0,
			pages: 0
		}));
		assert!(events().contains(&Event::EraPaid { era: 0, blocks: 0 }));
		assert!(Current::<Test>::get().is_none());
	});
}

#[test]
fn validators_beyond_the_bound_are_left_to_manual_claims() {
	new_test_ext().execute_with(|| {
		let many: Vec<_> = (1..=10).map(|v| (v, 0)).collect();
		close_era_zero(&many);
		run_block(2, quiet());
		run_block(3, quiet());
		let validators: BTreeSet<_> = paid().iter().map(|(_, v, _)| *v).collect();
		assert_eq!(validators.len(), 8);
	});
}

#[test]
fn paused_pays_nothing_but_keeps_queueing() {
	new_test_ext().execute_with(|| {
		elect(0, &nominators(4));
		set_active_era(0);
		run_block(1, full());
		AutoPayout::pause(frame_system::RawOrigin::Root.into()).unwrap();
		set_active_era(1);
		for n in 2..50 {
			run_block(n, quiet());
		}
		assert!(paid().is_empty());
		assert_eq!(Queue::<Test>::get().into_inner(), vec![0]);
		AutoPayout::resume(frame_system::RawOrigin::Root.into()).unwrap();
		pay_until_settled(0, 50, WINDOW, quiet());
	});
}

#[test]
fn too_little_idle_weight_does_nothing() {
	new_test_ext().execute_with(|| {
		close_era_zero(&nominators(4));
		let idle = idle_only(2, Weight::from_parts(1, u64::MAX));
		assert_eq!(idle, Weight::zero());
		assert!(paid().is_empty());
	});
}

#[test]
fn a_page_that_does_not_fit_waits_for_the_next_block() {
	new_test_ext().execute_with(|| {
		close_era_zero(&[(1, 4)]);
		// Enough to start the era, not to pay its 9 ms page.
		let idle = idle_only(2, Weight::from_parts(12_000_000, u64::MAX));
		assert!(idle.ref_time() <= 12_000_000);
		assert!(paid().is_empty());
		assert_eq!(Current::<Test>::get().map(|s| s.era), Some(0));
		idle_only(3, quiet());
		assert_eq!(paid(), [(0, 1, 0)]);
	});
}

#[test]
fn a_refused_page_costs_no_more_than_its_estimate() {
	new_test_ext().execute_with(|| {
		close_era_zero(&[(1, 0)]);
		refuse(0, 1, 0);
		// Room for the era start and one empty page, not for a full one.
		let room = Weight::from_parts(
			AutoPayout::start_weight().ref_time() + page_weight(0).ref_time() + 100_000,
			u64::MAX,
		);
		let idle = idle_only(2, room);
		assert!(idle.all_lte(room));
		assert_eq!(pay_calls(), 1);
		assert!(Current::<Test>::get().is_none_or(|s| s.is_done()));
	});
}

#[test]
fn a_floor_too_small_for_a_page_still_pays_one_a_block() {
	new_test_ext().execute_with(|| {
		close_era_zero(&nominators(40));
		// As if a weight change left a governance-set floor below a full page.
		Limits::<Test>::put(crate::PayoutLimits {
			floor: sp_runtime::Perbill::from_parts(5_000_000),
			..Limits::<Test>::get()
		});
		for n in 2..2 + WINDOW {
			System::set_block_number(n);
			let used = <AutoPayout as frame_support::traits::Hooks<u64>>::on_initialize(n);
			assert!(
				used.all_lte(AutoPayout::largest_step()),
				"over the largest step at {n}"
			);
		}
		assert!(
			era_settled(0) && Current::<Test>::get().is_none(),
			"a full chain stalled"
		);
	});
}

/// Staking's refund counts only the nominators it paid: a page whose nominators
/// take nothing (payee `None`) reports almost no weight. Each page is charged
/// its estimate anyway, so a block pays no more pages than its budget prices.
#[test]
fn a_page_is_charged_its_estimate_whatever_staking_reports() {
	let paid_in_one_idle_block = |cheap: bool| {
		let mut count = 0;
		new_test_ext().execute_with(|| {
			close_era_zero(&nominators(10 * PAGE_SIZE));
			run_block(2, full());
			set_cheap_refund(cheap);
			let before = paid().len();
			run_block(3, quiet());
			count = paid().len() - before;
			set_cheap_refund(false);
		});
		count
	};
	let honest = paid_in_one_idle_block(false);
	assert!(honest > 0);
	assert_eq!(paid_in_one_idle_block(true), honest);
}

/// A call the runtime filtered did no work and is charged none: a blocked page
/// does not eat a page's weight every block.
#[test]
fn a_blocked_page_costs_no_page() {
	new_test_ext().execute_with(|| {
		close_era_zero(&nominators(10 * PAGE_SIZE));
		set_blocked(true);
		let (_, idle) = run_block(2, quiet());
		assert!(idle.ref_time() < page_weight(PAGE_SIZE).ref_time());
		set_blocked(false);
	});
}
