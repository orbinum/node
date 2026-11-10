//! Eras past the history pruned from `on_idle` (`staking::pruning`): over the
//! blocks that follow, never in a heavy block and never above its share of the
//! block.

use crate::test_utils::{
	blocks::{run_block, run_to_era, settle},
	network::{charlie, with_validators},
};
use crate::{
	configs::{staking::EraPruningBlockShare, system::BlockWeights},
	staking::{params::HISTORY_DEPTH, HeavyBlocks},
	AutoPayout, BlockNumber, EraPruning, Runtime, RuntimeEvent, RuntimeOrigin, System,
};
use frame_support::{
	assert_ok,
	traits::{Contains, OnIdle},
	weights::Weight,
};
use pallet_staking_async::{self as staking, EraPruningState, PruningStep};

const PRUNED: [u32; 2] = [1, 2];

/// Eras 1 to 3 with real data (exposures, prefs, points, paid rewards), then
/// the active era moved past the history so that eras 1 and 2 are marked, as
/// staking marks them when eras 86 and 87 start. Automatic payment is paused so
/// it does not react to the jump.
fn with_marked_eras<R>(run: impl FnOnce() -> R) -> R {
	with_validators(|| {
		run_to_era(4);
		for n in 1..=50 {
			run_block(System::block_number() + n);
		}
		// An election left running would make every block heavy.
		settle();
		for era in PRUNED {
			assert!(!staking::Pallet::<Runtime>::api_pending_rewards(
				era,
				charlie()
			));
			assert!(has_data(era), "era {era} has data to prune");
		}
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		let active = PRUNED[1] + HISTORY_DEPTH + 1;
		staking::ActiveEra::<Runtime>::put(staking::ActiveEraInfo {
			index: active,
			start: None,
		});
		staking::CurrentEra::<Runtime>::put(active);
		for era in PRUNED {
			EraPruningState::<Runtime>::insert(era, PruningStep::ErasStakersPaged);
		}
		run()
	})
}

fn has_data(era: u32) -> bool {
	staking::ErasStakersPaged::<Runtime>::iter_prefix((era,))
		.next()
		.is_some()
		|| staking::ErasStakersOverview::<Runtime>::iter_prefix(era)
			.next()
			.is_some()
		|| staking::ErasValidatorPrefs::<Runtime>::iter_prefix(era)
			.next()
			.is_some()
		|| staking::ClaimedRewards::<Runtime>::iter_prefix(era)
			.next()
			.is_some()
		|| staking::ErasValidatorReward::<Runtime>::contains_key(era)
		|| staking::ErasRewardPoints::<Runtime>::contains_key(era)
		|| staking::ErasTotalStake::<Runtime>::contains_key(era)
}

/// The next block after `n` that is not heavy.
fn next_light_block(n: BlockNumber) -> BlockNumber {
	(n + 1..)
		.find(|b| !HeavyBlocks::contains(b))
		.expect("a light block")
}

fn pruned_eras() -> Vec<u32> {
	System::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::Staking(staking::Event::EraPruned { index }) => Some(index),
			_ => None,
		})
		.collect()
}

#[test]
fn marked_eras_are_pruned_over_the_following_blocks() {
	with_marked_eras(|| {
		let mut n = System::block_number();
		for _ in 0..40 {
			if EraPruningState::<Runtime>::iter().next().is_none() {
				break;
			}
			n = next_light_block(n);
			run_block(n);
		}
		for era in PRUNED {
			assert!(!has_data(era), "era {era} still has data");
			assert!(!EraPruningState::<Runtime>::contains_key(era));
		}
		let mut events = pruned_eras();
		events.sort();
		assert_eq!(events, PRUNED.to_vec());
		// Later eras are untouched.
		assert!(has_data(3));
	});
}

#[test]
fn pruning_waits_for_light_blocks_with_room() {
	with_marked_eras(|| {
		let state = || EraPruningState::<Runtime>::iter().collect::<Vec<_>>();
		let before = state();
		let budget = EraPruning::budget();
		let light = next_light_block(System::block_number());

		// Not enough weight left: nothing is read or done.
		let short = budget.saturating_sub(Weight::from_parts(1, 0));
		assert_eq!(EraPruning::on_idle(light, short), Weight::zero());
		assert_eq!(state(), before);

		// A session's last block: only the check is paid.
		let boundary = (light..).find(HeavyBlocks::contains).unwrap();
		let max = BlockWeights::get().max_block;
		assert!(EraPruning::on_idle(boundary, max).all_lt(budget));
		assert_eq!(state(), before);

		// The election's blocks.
		pallet_paged_election::CurrentPhase::<Runtime>::put(pallet_paged_election::Phase::Voters(
			0,
		));
		assert!(EraPruning::on_idle(light, max).all_lt(budget));
		assert_eq!(state(), before);
		pallet_paged_election::CurrentPhase::<Runtime>::put(pallet_paged_election::Phase::Off);

		// Light, with room: one step.
		assert_ne!(EraPruning::on_idle(light, max), Weight::zero());
		assert_ne!(state(), before);
	});
}

/// An era whose step fails is reported and skipped; the others are pruned.
#[test]
fn a_failing_era_does_not_hold_the_others() {
	with_marked_eras(|| {
		// Still within the history, so staking refuses to prune it; and the first
		// era pruning reads, so a failure that held the queue would stop it all.
		let kept = (PRUNED[1] + 1..PRUNED[1] + 40)
			.find(|era| {
				EraPruningState::<Runtime>::insert(era, PruningStep::ErasStakersPaged);
				let first = EraPruningState::<Runtime>::iter_keys().next() == Some(*era);
				if !first {
					EraPruningState::<Runtime>::remove(era);
				}
				first
			})
			.expect("an era read before the marked ones");
		let mut n = System::block_number();
		for _ in 0..40 {
			if PRUNED
				.iter()
				.all(|era| !EraPruningState::<Runtime>::contains_key(era))
			{
				break;
			}
			n = next_light_block(n);
			run_block(n);
		}
		for era in PRUNED {
			assert!(!has_data(era), "era {era} still has data");
		}
		assert!(EraPruningState::<Runtime>::contains_key(kept));
		assert!(has_data(3), "eras within the history keep their data");
		assert!(System::events().iter().any(|r| matches!(
			&r.event,
			RuntimeEvent::EraPruning(crate::staking::pruning::Event::PruningFailed { era, .. })
				if *era == kept
		)));
	});
}

#[test]
fn a_block_prunes_within_its_share() {
	let (budget, share) = (EraPruning::budget(), EraPruning::share());
	let max = BlockWeights::get().max_block;
	assert_eq!(share, EraPruningBlockShare::get() * max);
	assert!(budget.all_lte(share), "{budget:?} over {share:?}");

	// Blocks until both eras are pruned, each given `limit` and never over `cap`.
	let prune_all = |limit: Weight, cap: Weight| {
		with_marked_eras(|| {
			let mut n = System::block_number();
			let mut blocks = 0;
			while EraPruningState::<Runtime>::iter().next().is_some() {
				n = next_light_block(n);
				let used = EraPruning::on_idle(n, limit);
				assert!(used.all_lte(cap), "block {n}: {used:?} over {cap:?}");
				blocks += 1;
				assert!(blocks < 100, "pruning never finishes");
			}
			assert!(!has_data(1) && !has_data(2));
			blocks
		})
	};

	// Room for one step: one step a block. Each era takes several steps.
	let one_step = prune_all(budget, budget);
	assert!(one_step >= 2 * 9, "{one_step} blocks");

	// A whole block: as many steps as fit the share, never over it, so never slower.
	let whole = prune_all(max, share);
	assert!(
		whole <= one_step,
		"{whole} blocks with a whole block, {one_step} with one step"
	);
}

fn failures(era: u32) -> usize {
	System::events()
		.iter()
		.filter(|r| {
			matches!(
				&r.event,
				RuntimeEvent::EraPruning(crate::staking::pruning::Event::PruningFailed { era: e, .. })
					if *e == era
			)
		})
		.count()
}

/// An era whose step fails is reported once and tried again only after
/// `RetryAfter` blocks, not every block.
#[test]
fn a_failing_era_is_reported_once() {
	use crate::staking::pruning::FailedEras;
	with_marked_eras(|| {
		// Within the history: staking refuses to prune it.
		let kept = PRUNED[1] + 10;
		EraPruningState::<Runtime>::insert(kept, PruningStep::ErasStakersPaged);
		let mut n = System::block_number();
		for _ in 0..40 {
			n = next_light_block(n);
			run_block(n);
		}
		assert_eq!(failures(kept), 1);
		let retry = FailedEras::<Runtime>::get()
			.iter()
			.find_map(|(era, retry)| (*era == kept).then_some(*retry))
			.expect("remembered");
		assert!(retry > n, "not due yet");
		for era in PRUNED {
			assert!(!has_data(era), "era {era} still has data");
		}

		// Due again: tried, still failing, not reported again.
		let due = next_light_block(retry - 1);
		System::set_block_number(due);
		let max = BlockWeights::get().max_block;
		EraPruning::on_idle(due, max);
		assert_eq!(failures(kept), 1);
		let next = FailedEras::<Runtime>::get()
			.iter()
			.find_map(|(era, retry)| (*era == kept).then_some(*retry))
			.expect("still remembered");
		assert!(next > due, "tried again at {due}");

		// Pruned meanwhile by someone else: forgotten.
		EraPruningState::<Runtime>::remove(kept);
		let later = next_light_block(next - 1);
		EraPruning::on_idle(later, max);
		assert!(FailedEras::<Runtime>::get().is_empty());
	});
}

/// Pruning stays clear of the eras automatic payment still holds, even with
/// its queue full: staking only prunes eras past the history it pays from.
#[test]
fn pruning_never_touches_eras_waiting_for_payment() {
	with_marked_eras(|| {
		let active = PRUNED[1] + HISTORY_DEPTH + 1;
		let waiting: Vec<u32> = (active - HISTORY_DEPTH..active).collect();
		pallet_auto_payout::LastActiveEra::<Runtime>::put(active);
		pallet_auto_payout::Queue::<Runtime>::put(frame_support::BoundedVec::truncate_from(
			waiting.clone(),
		));
		assert_eq!(waiting.len() as u32, HISTORY_DEPTH);
		// Marked by mistake, the oldest waiting era is refused all the same.
		EraPruningState::<Runtime>::insert(waiting[0], PruningStep::ErasStakersPaged);
		let mut n = System::block_number();
		for _ in 0..40 {
			n = next_light_block(n);
			run_block(n);
		}
		for era in PRUNED {
			assert!(!has_data(era), "era {era} still has data");
		}
		assert!(has_data(waiting[0]), "a waiting era lost its data");
		assert!(EraPruningState::<Runtime>::contains_key(waiting[0]));
		assert_eq!(
			pallet_auto_payout::Queue::<Runtime>::get().into_inner(),
			waiting
		);
	});
}
