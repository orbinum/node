//! Timing and weight per step for 12,500 and 25,000 voters, natively. Run with
//! `cargo test --release -p pallet-paged-election report -- --ignored --nocapture`.
//! Wall time here is native, without staking's reads; the weights are the
//! placeholders in `weights.rs`.

use super::util::*;
use crate::{CurrentPhase, ElectionProvider, PageInfos, Phase, tests::mock::*};
use frame_support::weights::WeightMeter;
use std::{collections::BTreeMap, time::Instant};

#[derive(Default)]
struct Kind {
	steps: u32,
	max_weight: u64,
	max_us: f64,
	total_us: f64,
}

fn pct(ref_time: u64) -> f64 {
	ref_time as f64 * 100.0 / MAX_BLOCK as f64
}

/// Least squares for `t = c + k·a` over pages of equal size: `c` is a page of
/// scanned voters, `k` the extra for each approving one.
fn fit(samples: &[(f64, f64)]) -> (f64, f64) {
	let n = samples.len() as f64;
	let (sa, st) = samples
		.iter()
		.fold((0.0, 0.0), |(a, t), s| (a + s.0, t + s.1));
	let (ma, mt) = (sa / n, st / n);
	let (cov, var) = samples.iter().fold((0.0, 0.0), |(c, v), s| {
		(c + (s.0 - ma) * (s.1 - mt), v + (s.0 - ma).powi(2))
	});
	let k = cov / var;
	(mt - k * ma, k)
}

fn report(voters: u32, stakes: Stakes) {
	let mut inst = instance(&mut Rng(42), voters, 256, 100, stakes);
	inst.voters.truncate(voters as usize);
	new_test_ext().execute_with(|| {
		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
		let blocks = run_election(false).blocks;

		set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
		assert_eq!(PagedElection::start(), Ok(()));
		let mut kinds: BTreeMap<&str, Kind> = BTreeMap::new();
		let mut applies = Vec::new();
		let mut phase = CurrentPhase::<Test>::get();
		loop {
			let kind = match phase {
				Phase::Targets => "1 snapshot targets",
				Phase::Voters(_) => "2 snapshot voters",
				Phase::Select => "3 select winner",
				Phase::Apply { .. } => "4 apply page",
				_ => break,
			};
			let counts = match phase {
				Phase::Apply { page, winner } => PageInfos::<Test>::get(page)
					.map(|i| (i.voters - i.approvers_of(winner), i.approvers_of(winner))),
				_ => None,
			};
			let mut meter = WeightMeter::new();
			let start = Instant::now();
			phase = PagedElection::step(1, phase, &mut meter).expect("unlimited meter");
			let us = start.elapsed().as_secs_f64() * 1e6;
			if let Some((n, a)) = counts.filter(|c| c.0 + c.1 == VoterSnapshotPerBlock::get()) {
				let _ = n;
				applies.push((f64::from(a), us));
			}
			let k = kinds.entry(kind).or_default();
			k.steps += 1;
			k.max_weight = k.max_weight.max(meter.consumed().ref_time());
			k.max_us = k.max_us.max(us);
			k.total_us += us;
		}
		let declared = PagedElection::export_weight().ref_time();
		for page in (0..Pages::get()).rev() {
			let start = Instant::now();
			PagedElection::elect(page).unwrap();
			let us = start.elapsed().as_secs_f64() * 1e6;
			let k = kinds.entry("5 export page").or_default();
			k.steps += 1;
			k.max_weight = declared;
			k.max_us = k.max_us.max(us);
			k.total_us += us;
		}

		println!(
			"\n== {voters} voters ({stakes:?}), 256 targets, 100 seats, {} pages of {} ==",
			Pages::get(),
			VoterSnapshotPerBlock::get()
		);
		println!(
			"{:<20} {:>6} {:>16} {:>14} {:>14} {:>12}",
			"step", "count", "max weight %", "max wall ms", "max wall %", "total ms"
		);
		for (name, k) in &kinds {
			println!(
				"{:<20} {:>6} {:>15.2}% {:>14.3} {:>13.3}% {:>12.1}",
				name,
				k.steps,
				pct(k.max_weight),
				k.max_us / 1e3,
				k.max_us * 100.0 / 2e6,
				k.total_us / 1e3
			);
		}
		let (page, extra) = fit(&applies);
		println!(
			"apply on a full page: {page:.1} µs scanning, +{:.1} ns per approving voter",
			extra * 1e3
		);
		println!(
			"blocks at {:?} budget: {blocks} (duration bound {}), budget {:.0}% of a 2 s block",
			RoundBudget::get(),
			PagedElection::duration_bound(),
			pct(budget().ref_time())
		);
	});
}

#[test]
#[ignore]
fn report_12_500_voters() {
	report(12_500, Stakes::Realistic);
}

#[test]
#[ignore]
fn report_25_000_voters() {
	report(25_000, Stakes::Realistic);
}

/// Everyone votes the same candidates: the heaviest rounds.
#[test]
#[ignore]
fn report_25_000_concentrated_voters() {
	report(25_000, Stakes::Concentrated);
}
