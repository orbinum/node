//! Random instances and the upstream reference they are checked against.

use crate::tests::mock::*;
use frame_election_provider_support::{BoundedSupportsOf, ExtendedBalance};
use sp_npos_elections::{StakedAssignment, seq_phragmen};
use sp_runtime::Perquintill;
use std::collections::{BTreeMap, BTreeSet};

/// A small deterministic generator; no dependency needed.
pub struct Rng(pub u64);
impl Rng {
	pub fn next(&mut self) -> u64 {
		self.0 = self
			.0
			.wrapping_mul(6364136223846793005)
			.wrapping_add(1442695040888963407);
		self.0 >> 33
	}
	pub fn below(&mut self, n: u64) -> u64 {
		if n == 0 { 0 } else { self.wide() % n }
	}
	pub fn chance(&mut self, percent: u64) -> bool {
		self.below(100) < percent
	}
	/// A full 64-bit value.
	pub fn wide(&mut self) -> u64 {
		(self.next() << 32) ^ self.next()
	}
}

/// Accounts: targets from 1, voters from 1,000,000, non-candidates from
/// 900,000.
pub const VOTER_BASE: AccountId = 1_000_000;
pub const STRANGER_BASE: AccountId = 900_000;

#[derive(Clone, Debug)]
pub struct Instance {
	pub targets: Vec<AccountId>,
	pub voters: Vec<Voter>,
	pub desired: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum Stakes {
	/// Realistic: 1 to 10,000 tokens of 10^18 units, and self-votes.
	Realistic,
	/// 1-unit voters, whales near `u64::MAX`, tiny-approval candidates,
	/// votes for non-candidates and repeats, zero stakes.
	Adversarial,
	/// Everyone votes the same candidates: every voter approves every early
	/// winner, the heaviest case for the rounds.
	Concentrated,
}

/// `voters` voters over `targets` targets, each with 1 to 16 votes.
pub fn instance(
	rng: &mut Rng,
	voters: u32,
	targets: u32,
	desired: u32,
	stakes: Stakes,
) -> Instance {
	let ids: Vec<AccountId> = (1..=u64::from(targets)).collect();
	let unit: u64 = 1_000_000_000_000_000_000;
	let mut list = Vec::with_capacity(voters as usize);
	for i in 0..voters {
		let who = VOTER_BASE + u64::from(i);
		let count = 1 + rng.below(u64::from(MAX_VOTES)) as usize;
		let mut votes = Vec::with_capacity(count);
		match stakes {
			Stakes::Concentrated => votes.extend(ids.iter().take(count)),
			_ => {
				while votes.len() < count.min(ids.len()) {
					let t = ids[rng.below(ids.len() as u64) as usize];
					if !votes.contains(&t) {
						votes.push(t);
					}
				}
			}
		}
		let stake = match stakes {
			Stakes::Realistic | Stakes::Concentrated => (1 + rng.below(10_000)) * unit,
			Stakes::Adversarial => match rng.below(10) {
				0 => 1,
				1 => u64::MAX - rng.below(1 << 20),
				2 => 0,
				3 => rng.wide(),
				_ => 1 + rng.below(1 << 40),
			},
		};
		if let Stakes::Adversarial = stakes {
			if rng.chance(20) && !votes.is_empty() {
				// Repeat a vote, and vote for someone who is not a candidate.
				let again = votes[rng.below(votes.len() as u64) as usize];
				votes.insert(rng.below(votes.len() as u64 + 1) as usize, again);
				votes.truncate(MAX_VOTES as usize);
			}
			if rng.chance(20) && votes.len() < MAX_VOTES as usize {
				votes.push(STRANGER_BASE + rng.below(5));
			}
		}
		list.push((who, stake, votes));
	}
	if let Stakes::Adversarial = stakes {
		// Tiny-approval candidates: backed by a single 1-unit voter.
		for (k, &t) in ids.iter().rev().take(3).enumerate() {
			list.push((VOTER_BASE + u64::from(voters) + k as u64, 1, vec![t]));
		}
	}
	if let Stakes::Realistic = stakes {
		// Validators back themselves.
		for &t in &ids {
			list.push((t, (10_000 + rng.below(100_000)) * unit, vec![t]));
		}
	}
	Instance {
		targets: ids,
		voters: list,
		desired,
	}
}

/// Upstream's election on the same input.
pub struct Reference {
	pub winners: Vec<(AccountId, ExtendedBalance)>,
	/// Each voter's ratios, normalised.
	pub assignments: BTreeMap<AccountId, Vec<(AccountId, Perquintill)>>,
}

pub fn reference(inst: &Instance) -> Reference {
	let result = seq_phragmen::<AccountId, Perquintill>(
		inst.desired as usize,
		inst.targets.clone(),
		inst.voters.clone(),
		None,
	)
	.expect("upstream election works");
	let assignments = result
		.assignments
		.into_iter()
		.map(|a| (a.who, a.distribution))
		.collect();
	Reference {
		winners: result.winners,
		assignments,
	}
}

/// Our supports per voter, in its vote order, converted to ratios the way
/// upstream converts its edge weights.
pub fn ratios(
	inst: &Instance,
	pages: &[BoundedSupportsOf<PagedElection>],
) -> BTreeMap<AccountId, Vec<(AccountId, Perquintill)>> {
	let mut edges: BTreeMap<AccountId, BTreeMap<AccountId, ExtendedBalance>> = BTreeMap::new();
	for page in pages {
		for (winner, support) in page.iter() {
			for (voter, weight) in support.voters.iter() {
				let previous = edges.entry(*voter).or_default().insert(*winner, *weight);
				assert!(previous.is_none(), "one edge per voter and winner");
			}
		}
	}
	let mut out = BTreeMap::new();
	for (who, stake, votes) in &inst.voters {
		let Some(weights) = edges.remove(who) else {
			continue;
		};
		let mut seen = BTreeSet::new();
		let distribution: Vec<_> = votes
			.iter()
			.filter(|t| seen.insert(**t))
			.filter_map(|t| weights.get(t).map(|w| (*t, *w)))
			.collect();
		assert_eq!(
			distribution.iter().map(|(_, w)| *w).sum::<u128>(),
			u128::from(*stake),
			"a voter's edges sum to its stake"
		);
		let mut assignment = StakedAssignment {
			who: *who,
			distribution,
		}
		.into_assignment();
		assignment.try_normalize().expect("ratios normalise");
		out.insert(*who, assignment.distribution);
	}
	assert!(edges.is_empty(), "every backer is a voter");
	out
}

/// Each winner's total over all pages.
pub fn totals(pages: &[BoundedSupportsOf<PagedElection>]) -> BTreeMap<AccountId, ExtendedBalance> {
	let mut out = BTreeMap::new();
	for page in pages {
		for (winner, support) in page.iter() {
			assert_eq!(
				support.total,
				support.voters.iter().map(|(_, w)| *w).sum::<u128>(),
				"a support's total is its backers' sum"
			);
			*out.entry(*winner).or_default() += support.total;
		}
	}
	out
}

/// Runs `inst` through the pallet and upstream and checks they agree:
/// winners in order, each winner's total exactly, and every voter's edges.
pub fn check_parity(inst: &Instance, checked: bool) -> Outcome {
	set_data(inst.targets.clone(), inst.voters.clone(), inst.desired);
	let outcome = run_election(checked);
	let expected = reference(inst);

	let ours: Vec<AccountId> = outcome.winners.iter().map(|w| w.0).collect();
	let theirs: Vec<AccountId> = expected.winners.iter().map(|w| w.0).collect();
	assert_eq!(ours, theirs, "same winners in the same order");

	let totals = totals(&outcome.pages);
	for (winner, backed) in &expected.winners {
		assert_eq!(
			totals.get(winner).copied().unwrap_or(0),
			*backed,
			"winner {winner}'s total"
		);
	}
	assert!(
		totals.keys().all(|w| ours.contains(w)),
		"only winners are supported"
	);
	assert_eq!(
		ratios(inst, &outcome.pages),
		expected.assignments,
		"every voter's edges"
	);
	outcome
}
