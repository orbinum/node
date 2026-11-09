//! Benchmarks for each `on_poll` step, staking's page fetch and `abort`. The
//! snapshot steps go through `Config::DataProvider`, so in the runtime they
//! price staking's own reads; the round steps run on a synthetic snapshot in
//! its worst shape.

use crate::phragmen::Accumulator;
use crate::*;
use alloc::{vec, vec::Vec};
use frame_benchmarking::v2::*;
use frame_election_provider_support::{ElectionDataProvider, ElectionProvider, ExtendedBalance};
use frame_support::{
	BoundedVec,
	traits::{EnsureOrigin, Get},
	weights::WeightMeter,
};

const SEED: u32 = 0;

fn target<T: Config>(i: u32) -> T::AccountId {
	account("target", i, SEED)
}

fn voter<T: Config>(i: u32) -> T::AccountId {
	account("voter", i, SEED)
}

/// A large stake, so the 256-bit divisions take their long path.
fn stake(i: u32) -> u64 {
	(1 << 60) + u64::from(i)
}

fn max_targets<T: Config>() -> u32 {
	T::MaxTargets::get()
}

fn msp<T: Config>() -> u32 {
	T::Pages::get().saturating_sub(1)
}

/// Staking with `t` targets and `v` voters, each with full votes.
fn provide<T: Config>(t: u32, v: u32) {
	T::DataProvider::clear();
	for i in 0..t {
		T::DataProvider::add_target(target::<T>(i));
	}
	let votes = MaxVotesOf::<T>::get().min(t.max(1));
	for i in 0..v {
		let list: Vec<_> = (0..votes)
			.map(|k| target::<T>((i + k) % t.max(1)))
			.collect();
		T::DataProvider::add_voter(voter::<T>(i), stake(i), BoundedVec::truncate_from(list));
	}
	T::DataProvider::set_desired_targets(T::MaxWinnersPerPage::get().min(t));
}

/// A snapshot of `t` targets whose first `w` are elected, with growing scores.
fn snapshot<T: Config>(t: u32, w: u32, to_elect: u32) {
	let targets: Vec<_> = (0..t).map(target::<T>).collect();
	Targets::<T>::put(BoundedVec::truncate_from(targets));
	let mut sum = Accumulator::default();
	let _ = sum.add(1 << 100);
	let candidates = (0..t)
		.map(|i| Candidate {
			approval: ExtendedBalance::from(stake(i)) << 12,
			sum,
		})
		.collect();
	Candidates::<T>::put(BoundedVec::truncate_from(candidates));
	let winners = (0..w)
		.map(|i| (i as TargetIndex, (1u128 << 110) + (u128::from(i) << 100)))
		.collect();
	Winners::<T>::put(BoundedVec::truncate_from(winners));
	Meta::<T>::put(ElectionMeta {
		started: frame_system::Pallet::<T>::block_number(),
		targets: t,
		desired: to_elect,
		to_elect,
		..Default::default()
	});
}

fn store_page<T: Config>(page: u32, voters: Vec<VoterOf<T>>, targets: u32) {
	let mut approvers = vec![0u32; targets as usize];
	for v in &voters {
		for &t in v.votes.iter() {
			approvers[usize::from(t)] += 1;
		}
	}
	PageInfos::<T>::insert(
		page,
		PageInfo {
			voters: voters.len() as u32,
			approvers: BoundedVec::truncate_from(approvers),
		},
	);
	VoterPages::<T>::insert(page, BoundedVec::truncate_from(voters));
}

fn snapshot_voter<T: Config>(i: u32, votes: impl Iterator<Item = u32>) -> VoterOf<T> {
	let votes: Vec<_> = votes.map(|t| t as TargetIndex).collect();
	SnapshotVoter {
		who: voter::<T>(i),
		stake: stake(i),
		votes: BoundedVec::truncate_from(votes),
	}
}

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn snapshot_targets(t: Linear<1, { max_targets::<T>() }>) -> Result<(), BenchmarkError> {
		provide::<T>(t, 0);
		<Pallet<T> as ElectionProvider>::start().map_err(|_| "start")?;
		let mut meter = WeightMeter::new();

		#[block]
		{
			Pallet::<T>::snapshot_targets(&mut meter);
		}

		assert_eq!(CurrentPhase::<T>::get(), Phase::Voters(msp::<T>()));
		Ok(())
	}

	#[benchmark]
	fn snapshot_voters(
		v: Linear<1, { T::VoterSnapshotPerBlock::get() }>,
	) -> Result<(), BenchmarkError> {
		provide::<T>(max_targets::<T>(), v);
		<Pallet<T> as ElectionProvider>::start().map_err(|_| "start")?;
		let mut meter = WeightMeter::new();
		Pallet::<T>::snapshot_targets(&mut meter);

		#[block]
		{
			Pallet::<T>::snapshot_voters(msp::<T>(), &mut meter);
		}

		assert!(matches!(
			CurrentPhase::<T>::get(),
			Phase::Voters(_) | Phase::Select
		));
		Ok(())
	}

	#[benchmark]
	fn select_winner(t: Linear<1, { max_targets::<T>() }>) {
		let elected = T::MaxWinnersPerPage::get().min(t).saturating_sub(1);
		snapshot::<T>(t, elected, elected.saturating_add(2).min(t));
		CurrentPhase::<T>::put(Phase::Select);
		let now = frame_system::Pallet::<T>::block_number();
		let mut meter = WeightMeter::new();

		#[block]
		{
			Pallet::<T>::select(now, &mut meter);
		}

		assert_eq!(Winners::<T>::get().len() as u32, elected + 1);
	}

	/// `n` voters scanned, `a` approving the winner: target 0, elected after
	/// target 1, which they also approve, so each moves its contribution to
	/// its other votes from one load to the next.
	#[benchmark]
	fn apply_page(
		n: Linear<0, { T::VoterSnapshotPerBlock::get() / 2 }>,
		a: Linear<1, { T::VoterSnapshotPerBlock::get() / 2 }>,
	) {
		let t = max_targets::<T>();
		let votes = MaxVotesOf::<T>::get().min(t);
		snapshot::<T>(t, 0, 3);
		Winners::<T>::put(BoundedVec::truncate_from(vec![
			(1, 1u128 << 110),
			(0, 1u128 << 111),
		]));
		let page = msp::<T>();
		let approving = (0..a).map(|i| snapshot_voter::<T>(i, 0..votes));
		let scanned = (a..a + n).map(|i| snapshot_voter::<T>(i, 1..votes.saturating_add(1).min(t)));
		store_page::<T>(page, approving.chain(scanned).collect(), t);
		CurrentPhase::<T>::put(Phase::Apply { page, winner: 0 });
		let mut meter = WeightMeter::new();

		#[block]
		{
			Pallet::<T>::apply(page, 0, &mut meter);
		}

		assert!(!matches!(CurrentPhase::<T>::get(), Phase::Failed(_)));
	}

	/// Staking fetches a page of `v` voters whose votes all went to winners.
	#[benchmark]
	fn export_page(v: Linear<1, { T::VoterSnapshotPerBlock::get() }>) {
		let t = max_targets::<T>();
		let winners = T::MaxWinnersPerPage::get().min(t);
		let votes = MaxVotesOf::<T>::get().min(winners);
		snapshot::<T>(t, winners, winners);
		let page = msp::<T>();
		let voters = (0..v).map(|i| snapshot_voter::<T>(i, (0..votes).map(|k| (i + k) % winners)));
		store_page::<T>(page, voters.collect(), t);
		CurrentPhase::<T>::put(Phase::Done);

		#[block]
		{
			T::DataProvider::fetch_page(page);
		}

		assert!(page == 0 || CurrentPhase::<T>::get() == Phase::Done);
	}

	#[benchmark]
	fn abort() -> Result<(), BenchmarkError> {
		snapshot::<T>(1, 0, 1);
		CurrentPhase::<T>::put(Phase::Select);
		let origin =
			T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

		#[extrinsic_call]
		_(origin as T::RuntimeOrigin);

		assert_eq!(CurrentPhase::<T>::get(), Phase::Failed(FailReason::Aborted));
		Ok(())
	}

	impl_benchmark_test_suite!(
		Pallet,
		crate::tests::mock::new_test_ext(),
		crate::tests::mock::Test
	);
}
