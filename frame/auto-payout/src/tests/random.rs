// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Random chains: eras of random size, pages claimed by hand or refused, heavy
//! blocks and traffic from none to full. Every block stays within its shares,
//! the invariants hold, every page is paid at most once, and every era settles
//! in time.

use crate::{Current, Limits, Queue, tests::mock::*};
use frame_support::weights::Weight;
use std::collections::BTreeSet;

/// A small deterministic generator; no dependency needed.
struct Rng(u64);
impl Rng {
	fn next(&mut self) -> u64 {
		self.0 = self
			.0
			.wrapping_mul(6364136223846793005)
			.wrapping_add(1442695040888963407);
		self.0 >> 33
	}
	fn below(&mut self, n: u64) -> u64 {
		self.next() % n
	}
}

#[test]
fn random_chains_pay_every_era_within_budget_and_in_time() {
	for seed in 0..300 {
		new_test_ext().execute_with(|| run(seed));
	}
}

fn run(seed: u64) {
	let mut rng = Rng(seed);
	let eras = 1 + rng.below(4) as u32;
	set_active_era(0);
	run_block(1, full());

	let mut by_hand = BTreeSet::new();
	for era in 0..eras {
		let validators: Vec<_> = (1..=1 + rng.below(8))
			.map(|v| (v, rng.below(30) as u32))
			.collect();
		elect(era, &validators);
		for &(v, nominators) in &validators {
			for page in 0..nominators.div_ceil(PAGE_SIZE).max(1) {
				match rng.below(10) {
					0 => {
						claim(era, v, page);
						by_hand.insert((era, v, page));
					}
					1 => refuse(era, v, page),
					_ => {}
				}
			}
		}
	}
	set_active_era(eras);

	let limits = Limits::<Test>::get();
	let block = Weight::from_parts(MAX_BLOCK, u64::MAX);
	let deadline = 2 + u64::from(eras) * WINDOW;
	let mut settled_at = None;
	for n in 2..=deadline {
		if rng.below(5) == 0 {
			set_heavy(n);
		}
		let left = match rng.below(3) {
			0 => full(),
			1 => quiet(),
			_ => Weight::from_parts(rng.below(MAX_BLOCK / 10), u64::MAX),
		};
		let (init, idle) = run_block(n, left);
		assert!(
			init.ref_time() <= (limits.catch_up * block).ref_time(),
			"seed {seed}: on_initialize over its share at {n}"
		);
		assert!(
			idle.all_lte(left),
			"seed {seed}: on_idle over what was left at {n}"
		);
		if (0..eras).all(era_settled)
			&& Current::<Test>::get().is_none()
			&& Queue::<Test>::get().is_empty()
		{
			settled_at = Some(n);
			break;
		}
	}
	assert!(
		settled_at.is_some(),
		"seed {seed}: {eras} eras not settled by block {deadline}"
	);

	let paid = paid();
	let unique: BTreeSet<_> = paid.iter().collect();
	assert_eq!(unique.len(), paid.len(), "seed {seed}: a page paid twice");
	assert!(
		paid.iter().all(|p| !by_hand.contains(p)),
		"seed {seed}: paid a page someone had claimed"
	);
}
