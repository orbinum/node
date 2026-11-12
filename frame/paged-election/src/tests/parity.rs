// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The election matches `sp_npos_elections::seq_phragmen` (no balancing):
//! the same winners in the same order, each winner's total stake exactly, and
//! every voter's edges.

use super::util::*;
use crate::tests::mock::*;

/// Many small instances over few, small pages, so voters span pages.
#[test]
fn small_random_instances_match_upstream() {
	for seed in 0..400 {
		let mut rng = Rng(seed);
		Pages::set(1 + rng.below(4) as u32);
		VoterSnapshotPerBlock::set(1 + rng.below(12) as u32);
		let capacity = Pages::get() * VoterSnapshotPerBlock::get();
		let targets = 1 + rng.below(20) as u32;
		let stakes =
			[Stakes::Realistic, Stakes::Adversarial, Stakes::Concentrated][seed as usize % 3];
		let desired = rng.below(u64::from(targets) + 5) as u32;
		let voters = rng.below(u64::from(capacity) + 1) as u32;
		let mut inst = instance(&mut rng, voters, targets, desired, stakes);
		inst.voters.truncate(capacity as usize);
		new_test_ext().execute_with(|| {
			tight_budget(&mut rng);
			check_parity(&inst, true);
		});
	}
	reset_parameters();
}

/// Medium instances: a thousand voters over 8 pages, up to 100 seats.
#[test]
fn medium_random_instances_match_upstream() {
	VoterSnapshotPerBlock::set(150);
	for seed in 0..12 {
		let mut rng = Rng(1_000 + seed);
		let stakes =
			[Stakes::Realistic, Stakes::Adversarial, Stakes::Concentrated][seed as usize % 3];
		let targets = 50 + rng.below(250) as u32;
		let desired = (10 + rng.below(91) as u32).min(targets);
		let mut inst = instance(&mut rng, 1_000, targets, desired, stakes);
		inst.voters.truncate(1_200);
		new_test_ext().execute_with(|| {
			check_parity(&inst, seed < 3);
		});
	}
	reset_parameters();
}

fn large(voters: u32, stakes: Stakes, seed: u64) {
	let mut rng = Rng(seed);
	let mut inst = instance(&mut rng, voters, 300, 100, stakes);
	inst.voters.truncate(25_000);
	new_test_ext().execute_with(|| {
		let outcome = check_parity(&inst, false);
		assert_eq!(outcome.winners.len(), 100);
		assert!(outcome.blocks <= PagedElection::duration_bound());
	});
}

#[test]
fn large_12_500_voters_match_upstream() {
	large(12_500, Stakes::Realistic, 7);
}

#[test]
fn large_25_000_voters_match_upstream() {
	// 300 self-votes come on top; the snapshot holds 25,000.
	large(24_700, Stakes::Realistic, 8);
}

#[test]
fn large_adversarial_stakes_match_upstream() {
	large(24_997, Stakes::Adversarial, 9);
}

#[test]
fn large_concentrated_votes_match_upstream() {
	large(25_000, Stakes::Concentrated, 10);
}
