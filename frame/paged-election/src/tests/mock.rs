// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{self as pallet_paged_election, ElectionProvider, Phase};
use frame_election_provider_support::{
	BoundedSupportsOf, ElectionDataProvider, PageIndex, VoteWeight, bounds::DataProviderBounds,
	data_provider,
};
use frame_support::{
	BoundedVec, derive_impl, parameter_types,
	traits::{Get, Hooks},
	weights::{Weight, WeightMeter, constants::RocksDbWeight},
};
use frame_system::limits::BlockWeights;
use sp_runtime::{BuildStorage, Perbill};
use std::cell::RefCell;

pub type AccountId = u64;
pub type BlockNumber = u64;

/// A 2 s block: 2·10^12 ref-time.
pub const MAX_BLOCK: u64 = 2_000_000_000_000;
pub const MAX_VOTES: u32 = 16;

/// `(voter, stake, votes)`.
pub type Voter = (AccountId, VoteWeight, Vec<AccountId>);

// ── Mock staking ─────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct Data {
	pub targets: Vec<AccountId>,
	pub voters: Vec<Voter>,
	pub desired: u32,
	/// Next voter to page out, as staking's `VoterSnapshotStatus`.
	cursor: usize,
	pub fail_targets: bool,
	pub fail_voters: bool,
	pub fail_desired: bool,
	/// Hand out every remaining voter, past the page's bound.
	pub overfill: bool,
	/// Voter pages handed out, as `(page, voters)`.
	pub served: Vec<(PageIndex, usize)>,
}

thread_local! {
	static DATA: RefCell<Data> = RefCell::new(Data::default());
}

pub fn with_data<R>(f: impl FnOnce(&mut Data) -> R) -> R {
	DATA.with(|d| f(&mut d.borrow_mut()))
}

pub fn set_data(targets: Vec<AccountId>, voters: Vec<Voter>, desired: u32) {
	with_data(|d| {
		*d = Data {
			targets,
			voters,
			desired,
			..Default::default()
		}
	});
}

pub struct MockStaking;
impl ElectionDataProvider for MockStaking {
	type AccountId = AccountId;
	type BlockNumber = BlockNumber;
	type MaxVotesPerVoter = MaxVotesPerVoter;

	fn electable_targets(
		bounds: DataProviderBounds,
		_page: PageIndex,
	) -> data_provider::Result<Vec<AccountId>> {
		with_data(|d| {
			if d.fail_targets {
				return Err("targets unavailable");
			}
			if bounds.count.is_some_and(|c| d.targets.len() as u32 > c.0) {
				return Err("Target snapshot too big");
			}
			Ok(d.targets.clone())
		})
	}

	/// Pages voters in order from a cursor; page 0 resets it, as staking does.
	fn electing_voters(
		bounds: DataProviderBounds,
		page: PageIndex,
	) -> data_provider::Result<Vec<frame_election_provider_support::VoterOf<Self>>> {
		with_data(|d| {
			if d.fail_voters {
				return Err("voters unavailable");
			}
			let count = match bounds.count {
				Some(c) if !d.overfill => c.0 as usize,
				_ => usize::MAX,
			};
			let end = d.cursor.saturating_add(count).min(d.voters.len());
			let out: Vec<_> = d.voters[d.cursor..end]
				.iter()
				.map(|(who, stake, votes)| (*who, *stake, BoundedVec::truncate_from(votes.clone())))
				.collect();
			d.cursor = if page == 0 { 0 } else { end };
			d.served.push((page, out.len()));
			Ok(out)
		})
	}

	fn desired_targets() -> data_provider::Result<u32> {
		with_data(|d| {
			if d.fail_desired {
				Err("no seats")
			} else {
				Ok(d.desired)
			}
		})
	}

	fn next_election_prediction(_: BlockNumber) -> BlockNumber {
		0
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn add_voter(
		voter: AccountId,
		weight: VoteWeight,
		targets: BoundedVec<AccountId, Self::MaxVotesPerVoter>,
	) {
		with_data(|d| d.voters.push((voter, weight, targets.into_inner())));
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn add_target(target: AccountId) {
		with_data(|d| d.targets.push(target));
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn clear() {
		with_data(|d| *d = Data::default());
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn set_desired_targets(count: u32) {
		with_data(|d| d.desired = count);
	}

	/// Staking's fetch: the page from the election provider.
	#[cfg(feature = "runtime-benchmarks")]
	fn fetch_page(page: PageIndex) {
		let _ = PagedElection::elect(page);
	}
}

// ── Runtime ──────────────────────────────────────────────────────────────────

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		PagedElection: pallet_paged_election,
	}
);

parameter_types! {
	pub TestBlockWeights: BlockWeights =
		BlockWeights::simple_max(Weight::from_parts(MAX_BLOCK, u64::MAX));
	pub static Pages: u32 = 8;
	pub static VoterSnapshotPerBlock: u32 = 3_125;
	pub static MaxTargets: u32 = 512;
	pub static MaxWinners: u32 = 128;
	pub static RoundBudget: Perbill = Perbill::from_percent(40);
	pub static MaxVotesPerVoter: u32 = MAX_VOTES;
	/// Overrides of the backer bounds below.
	pub static MaxBackers: Option<u32> = None;
	pub static MaxBackersFinal: Option<u32> = None;
}

/// A page's voters, each backing a winner at most once.
pub struct MaxBackersPerWinner;
impl Get<u32> for MaxBackersPerWinner {
	fn get() -> u32 {
		MaxBackers::get().unwrap_or_else(VoterSnapshotPerBlock::get)
	}
}

/// Every voter.
pub struct MaxBackersPerWinnerFinal;
impl Get<u32> for MaxBackersPerWinnerFinal {
	fn get() -> u32 {
		MaxBackersFinal::get().unwrap_or_else(|| Pages::get() * VoterSnapshotPerBlock::get())
	}
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = sp_runtime::traits::IdentityLookup<AccountId>;
	type BlockWeights = TestBlockWeights;
	type DbWeight = RocksDbWeight;
}

impl pallet_paged_election::Config for Test {
	type DataProvider = MockStaking;
	type Pages = Pages;
	type VoterSnapshotPerBlock = VoterSnapshotPerBlock;
	type MaxTargets = MaxTargets;
	type MaxWinnersPerPage = MaxWinners;
	type MaxBackersPerWinner = MaxBackersPerWinner;
	type MaxBackersPerWinnerFinal = MaxBackersPerWinnerFinal;
	type RoundBudget = RoundBudget;
	type AdminOrigin = frame_system::EnsureRoot<AccountId>;
	type WeightInfo = crate::weights::SubstrateWeight<Test>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	DATA.with(|d| *d.borrow_mut() = Data::default());
	let storage = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.expect("genesis");
	let mut ext = sp_io::TestExternalities::new(storage);
	ext.execute_with(|| System::set_block_number(1));
	ext
}

/// Back to the defaults above.
pub fn reset_parameters() {
	Pages::set(8);
	VoterSnapshotPerBlock::set(3_125);
	MaxTargets::set(512);
	MaxWinners::set(128);
	RoundBudget::set(Perbill::from_percent(40));
	MaxVotesPerVoter::set(MAX_VOTES);
	MaxBackers::set(None);
	MaxBackersFinal::set(None);
}

/// A budget between the heaviest step and four times it, so an election
/// spreads over many blocks.
pub fn tight_budget(rng: &mut crate::tests::util::Rng) {
	RoundBudget::set(Perbill::from_percent(100));
	let step = PagedElection::snapshot_step()
		.max(PagedElection::round_step())
		.saturating_add(PagedElection::block_overhead())
		.ref_time();
	let budget = step + step / 100 + rng.below(3 * step);
	RoundBudget::set(Perbill::from_rational(budget, MAX_BLOCK).max(Perbill::from_parts(1)));
}

pub fn budget() -> Weight {
	PagedElection::budget()
}

/// Runs block `n`'s `on_poll` with the whole block available; returns what
/// the election consumed.
pub fn poll(n: BlockNumber) -> Weight {
	System::set_block_number(n);
	let mut meter = WeightMeter::with_limit(Weight::from_parts(MAX_BLOCK, u64::MAX));
	PagedElection::on_poll(n, &mut meter);
	meter.consumed()
}

/// A finished election as staking sees it.
pub struct Outcome {
	/// Winners in election order, with their scores.
	pub winners: Vec<(AccountId, u128)>,
	/// Blocks from `start` until `status` reported ready.
	pub blocks: u32,
	/// The most one block's `on_poll` consumed.
	pub heaviest: Weight,
	/// Pages from the most significant down to 0.
	pub pages: Vec<BoundedSupportsOf<PagedElection>>,
}

/// Starts an election in the current block and polls until ready, checking
/// the budget and, if `checked`, the invariants after every block; then
/// fetches every page as staking does.
pub fn run_election(checked: bool) -> Outcome {
	PagedElection::check_parameters();
	assert_eq!(PagedElection::start(), Ok(()));
	let budget = budget();
	let mut n = System::block_number();
	let (mut blocks, mut heaviest) = (0u32, Weight::zero());
	loop {
		let used = poll(n);
		blocks += 1;
		assert!(
			used.all_lte(budget),
			"block {n} used {used:?} over {budget:?}"
		);
		heaviest = heaviest.max(used);
		if checked {
			PagedElection::do_try_state().expect("invariants hold");
		}
		match PagedElection::status() {
			Ok(Some(_)) => break,
			Ok(None) => n += 1,
			Err(()) => panic!("election stopped"),
		}
		assert!(blocks < 10_000, "election never finished");
	}
	assert!(
		crate::CurrentPhase::<Test>::get() == Phase::Done,
		"election failed"
	);
	let targets = crate::Targets::<Test>::get();
	let winners = crate::Winners::<Test>::get()
		.iter()
		.map(|&(t, score)| (targets[usize::from(t)], score))
		.collect();
	let pages = (0..Pages::get())
		.rev()
		.map(|p| PagedElection::elect(p).expect("page exports"))
		.collect();
	Outcome {
		winners,
		blocks,
		heaviest,
		pages,
	}
}

/// What staking's `EraElectionPlanner` does once `status` reports ready: one
/// page per block from the most significant down to 0, a failed page logged
/// and skipped. If `status` stops reporting ready, staking fetches nothing
/// more and keeps waiting for the next page, so fewer results come back.
/// Returns each page's result and the winners it collected.
pub fn fetch_like_staking() -> (Vec<Result<u32, crate::ElectionError>>, Vec<AccountId>) {
	let mut results = Vec::new();
	let mut electable = std::collections::BTreeSet::new();
	let mut next = Some(Pages::get() - 1);
	while let Some(page) = next {
		if !matches!(PagedElection::status(), Ok(Some(_))) {
			break;
		}
		match PagedElection::elect(page) {
			Ok(supports) => {
				results.push(Ok(supports.len() as u32));
				electable.extend(supports.iter().map(|(w, _)| *w));
			}
			Err(e) => results.push(Err(e)),
		}
		next = page.checked_sub(1);
	}
	(results, electable.into_iter().collect())
}

pub fn events() -> Vec<pallet_paged_election::Event<Test>> {
	System::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::PagedElection(e) => Some(e),
			_ => None,
		})
		.collect()
}
