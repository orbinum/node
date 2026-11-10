//! Every block stays within the budget and what the block has left, and the
//! election finishes within `duration()`.

use super::util::*;
use crate::{CurrentPhase, ElectionProvider, Phase, tests::mock::*};
use frame_support::{
	traits::Hooks,
	weights::{Weight, WeightMeter},
};

#[test]
fn every_block_stays_within_budget_and_duration() {
	for seed in 0..60 {
		let mut rng = Rng(5_000 + seed);
		Pages::set(1 + rng.below(8) as u32);
		VoterSnapshotPerBlock::set(1 + rng.below(80) as u32);
		let capacity = Pages::get() * VoterSnapshotPerBlock::get();
		let stakes =
			[Stakes::Realistic, Stakes::Adversarial, Stakes::Concentrated][seed as usize % 3];
		let targets = 1 + rng.below(60) as u32;
		let desired = rng.below(u64::from(targets) + 3) as u32;
		let mut inst = instance(&mut rng, capacity, targets, desired, stakes);
		inst.voters.truncate(capacity as usize);
		new_test_ext().execute_with(|| {
			tight_budget(&mut rng);
			let outcome = check_parity(&inst, false);
			let bound = PagedElection::duration_bound();
			assert!(
				outcome.blocks <= bound,
				"seed {seed}: {} blocks over {bound}",
				outcome.blocks
			);
			assert_eq!(PagedElection::duration(), u64::from(bound));
		});
	}
	reset_parameters();
}

/// Everyone votes the same 16 candidates, with the default parameters: the
/// most a round can cost.
#[test]
fn the_heaviest_election_finishes_within_duration() {
	let mut inst = instance(&mut Rng(1), 25_000, 300, 100, Stakes::Concentrated);
	inst.voters
		.iter_mut()
		.for_each(|v| v.2 = (1..=16).collect());
	new_test_ext().execute_with(|| {
		let outcome = check_parity(&inst, false);
		assert!(outcome.blocks <= PagedElection::duration_bound());
		assert!(outcome.heaviest.all_lte(budget()));
	});
}

/// A busy block leaves the election less than its budget: it spends only what
/// is left, and makes progress once a step fits.
#[test]
fn spends_only_what_the_block_left() {
	let inst = instance(&mut Rng(3), 2_000, 50, 20, Stakes::Realistic);
	VoterSnapshotPerBlock::set(300);
	new_test_ext().execute_with(|| {
		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
		assert_eq!(PagedElection::start(), Ok(()));
		let mut rng = Rng(4);
		let mut n = 1;
		while !matches!(PagedElection::status(), Ok(Some(_))) {
			let left = Weight::from_parts(rng.below(MAX_BLOCK / 2), u64::MAX);
			let mut meter = WeightMeter::with_limit(left);
			PagedElection::on_poll(n, &mut meter);
			assert!(meter.consumed().all_lte(left.min(budget())));
			PagedElection::do_try_state().unwrap();
			n += 1;
			assert!(n < 1_000, "stuck in {:?}", CurrentPhase::<Test>::get());
		}
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Done);
	});
	reset_parameters();
}

#[test]
fn a_full_block_runs_nothing() {
	new_test_ext().execute_with(|| {
		set_data(vec![1, 2], vec![(10, 5, vec![1])], 1);
		assert_eq!(PagedElection::start(), Ok(()));
		let mut meter = WeightMeter::with_limit(Weight::zero());
		PagedElection::on_poll(1, &mut meter);
		assert_eq!(meter.consumed(), Weight::zero());
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Targets);
	});
}

#[test]
fn an_idle_block_reads_the_phase_only() {
	new_test_ext().execute_with(|| {
		assert_eq!(
			poll(1),
			<Test as frame_system::Config>::DbWeight::get().reads(1)
		);
	});
}

#[test]
fn a_smaller_budget_takes_longer() {
	let wide = PagedElection::duration_bound();
	RoundBudget::set(sp_runtime::Perbill::from_percent(30));
	let narrow = PagedElection::duration_bound();
	reset_parameters();
	assert!(narrow > wide, "{narrow} > {wide}");
}

/// Staking may walk past voters without stake, up to twice the page: a voter
/// step costs its worst case even when staking returns nobody, and the target
/// step likewise.
#[test]
fn a_voter_page_is_charged_its_worst_case_whatever_staking_returns() {
	use crate::WeightInfo;
	type W = crate::weights::SubstrateWeight<Test>;
	new_test_ext().execute_with(|| {
		set_data(vec![1], vec![], 1);
		assert_eq!(PagedElection::start(), Ok(()));
		let mut meter = WeightMeter::new();
		PagedElection::snapshot_targets(&mut meter);
		assert_eq!(meter.consumed(), W::snapshot_targets(MaxTargets::get()));
		let msp = Pages::get() - 1;
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Voters(msp));

		let mut meter = WeightMeter::new();
		PagedElection::snapshot_voters(msp, &mut meter);
		assert_eq!(with_data(|d| d.served.clone()), vec![(msp, 0)]);
		assert_eq!(
			meter.consumed(),
			W::snapshot_voters(VoterSnapshotPerBlock::get())
		);
	});
}
