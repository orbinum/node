// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Random chains: elections of random shape under random block load, with
//! starts, fetches and aborts out of turn. The invariants hold after every
//! block, out-of-turn calls change nothing, and every election that is not
//! aborted matches upstream.

use super::util::*;
use crate::{CurrentPhase, ElectionError, ElectionProvider, FailReason, Phase, tests::mock::*};
use frame_support::{
	traits::Hooks,
	weights::{Weight, WeightMeter},
};

#[test]
fn random_chains_keep_the_invariants() {
	for seed in 0..150 {
		new_test_ext().execute_with(|| run(seed));
	}
	reset_parameters();
}

fn run(seed: u64) {
	let mut rng = Rng(77_000 + seed);
	Pages::set(1 + rng.below(6) as u32);
	VoterSnapshotPerBlock::set(1 + rng.below(40) as u32);
	tight_budget(&mut rng);
	let capacity = Pages::get() * VoterSnapshotPerBlock::get();

	let mut n: u64 = 1;
	for _election in 0..3 {
		let stakes =
			[Stakes::Realistic, Stakes::Adversarial, Stakes::Concentrated][rng.below(3) as usize];
		let targets = rng.below(30) as u32;
		let desired = rng.below(u64::from(targets) + 3) as u32;
		let voters = rng.below(u64::from(capacity) + 1) as u32;
		let mut inst = instance(&mut rng, voters, targets, desired, stakes);
		inst.voters.truncate(capacity as usize);
		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);

		assert_eq!(PagedElection::start(), Ok(()));
		let mut aborted = false;
		while CurrentPhase::<Test>::get().is_computing() {
			System::set_block_number(n);
			let left = Weight::from_parts(rng.below(MAX_BLOCK), u64::MAX);
			let mut meter = WeightMeter::with_limit(left);
			PagedElection::on_poll(n, &mut meter);
			assert!(meter.consumed().all_lte(left.min(budget())));
			PagedElection::do_try_state().expect("invariants hold");

			let phase = CurrentPhase::<Test>::get();
			match rng.below(20) {
				0 => assert_eq!(PagedElection::start(), Err(ElectionError::Ongoing)),
				1 if phase.is_computing() => {
					let page = rng.below(u64::from(Pages::get())) as u32;
					assert_eq!(PagedElection::elect(page), Err(ElectionError::NotReady));
				}
				2 if rng.chance(30) => {
					assert!(PagedElection::abort(RuntimeOrigin::root()).is_ok());
					aborted = true;
				}
				_ => {}
			}
			if !aborted {
				assert_eq!(
					CurrentPhase::<Test>::get(),
					phase,
					"out-of-turn calls change nothing"
				);
			}
			PagedElection::do_try_state().expect("invariants hold");
			n += 1;
			assert!(n < 100_000);
		}

		if aborted {
			assert_eq!(
				CurrentPhase::<Test>::get(),
				Phase::Failed(FailReason::Aborted)
			);
			let (results, electable) = fetch_like_staking();
			assert!(results.iter().all(|r| r.is_err()) && electable.is_empty());
		} else {
			assert_eq!(CurrentPhase::<Test>::get(), Phase::Done);
			let targets = crate::Targets::<Test>::get();
			let ours: Vec<_> = crate::Winners::<Test>::get()
				.iter()
				.map(|w| targets[usize::from(w.0)])
				.collect();
			let pages: Vec<_> = (0..Pages::get())
				.rev()
				.map(|p| PagedElection::elect(p).unwrap())
				.collect();
			let expected = reference(&inst);
			assert_eq!(
				ours,
				expected.winners.iter().map(|w| w.0).collect::<Vec<_>>()
			);
			let totals = totals(&pages);
			for (w, backed) in &expected.winners {
				assert_eq!(totals.get(w).copied().unwrap_or(0), *backed);
			}
			assert_eq!(ratios(&inst, &pages), expected.assignments);
		}
		assert_eq!(CurrentPhase::<Test>::get(), Phase::Off);
		PagedElection::do_try_state().expect("invariants hold");
		// An idle block costs one read.
		assert_eq!(
			poll(n),
			<Test as frame_system::Config>::DbWeight::get().reads(1)
		);
		n += 1;
	}
}
