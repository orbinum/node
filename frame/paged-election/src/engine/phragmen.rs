//! Sequential Phragmén's arithmetic, exactly as `sp_npos_elections::seq_phragmen`
//! computes it, so the incremental election lands on the same integers.
//!
//! Upstream keeps scores and loads as `Rational128` numerators over
//! [`DEN`]` = u128::MAX` and adds them with `lazy_saturating_add`, which adds
//! numerators and saturates. In each round:
//!
//! - a candidate with approval `A` starts at `DEN / A`; one without approval
//!   scores `u128::MAX / 1`, above every other score ([`Rank::Unapproved`]);
//! - each voter with stake `b` and load `l` approving it adds
//!   `⌊l · b / A⌋` ([`contribution`]), and the sum saturates at `u128::MAX`;
//! - the lowest score wins, the first candidate on ties;
//! - the winner's voters take its score as their load.
//!
//! A voter's load is therefore the score of the last winner it approves, and
//! a sum of non-negative terms saturates the same in any order: the election
//! only keeps per-candidate sums ([`Accumulator`], exact so they can also be
//! decreased) and the winners' scores. [`distribute`] then splits each
//! voter's stake as upstream's backing step does.

use alloc::vec::Vec;
use frame_election_provider_support::{ExtendedBalance, VoteWeight};
use scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_npos_elections::StakedAssignment;
use sp_runtime::{Rounding, helpers_128bit::multiply_by_rational_with_rounding};

/// Denominator of every score and load.
pub const DEN: ExtendedBalance = ExtendedBalance::MAX;

/// `a · b / c` rounded down, `u128::MAX` when it does not fit, as upstream.
fn mul_div(a: ExtendedBalance, b: ExtendedBalance, c: ExtendedBalance) -> ExtendedBalance {
	multiply_by_rational_with_rounding(a, b, c, Rounding::Down).unwrap_or(ExtendedBalance::MAX)
}

/// A candidate's starting score, or `None` without approval.
pub fn base_score(approval: ExtendedBalance) -> Option<ExtendedBalance> {
	DEN.checked_div(approval)
}

/// What a voter with `stake` and `load` adds to a candidate's score. Never
/// overflows: `stake ≤ approval`, so the result is at most `load`.
pub fn contribution(
	load: ExtendedBalance,
	stake: ExtendedBalance,
	approval: ExtendedBalance,
) -> ExtendedBalance {
	mul_div(load, stake, approval)
}

/// A candidate's place in a round: lower wins. Variant order is the order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Rank {
	Scored(ExtendedBalance),
	Unapproved,
}

/// A candidate's rank from its approval and summed contributions, and whether
/// the score saturated.
pub fn rank(approval: ExtendedBalance, sum: &Accumulator) -> (Rank, bool) {
	match base_score(approval) {
		None => (Rank::Unapproved, false),
		Some(base) => match sum.to_u128().and_then(|s| base.checked_add(s)) {
			Some(score) => (Rank::Scored(score), false),
			None => (Rank::Scored(ExtendedBalance::MAX), true),
		},
	}
}

/// An exact sum of contributions, wide enough for `2^64` of them.
#[derive(
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	Clone,
	Copy,
	Default,
	PartialEq,
	Eq,
	Debug
)]
pub struct Accumulator {
	low: u128,
	high: u64,
}

impl Accumulator {
	pub fn to_u128(&self) -> Option<u128> {
		(self.high == 0).then_some(self.low)
	}

	/// `None` on overflow, leaving `self` unchanged.
	#[must_use]
	pub fn add(&mut self, x: u128) -> Option<()> {
		let (low, carry) = self.low.overflowing_add(x);
		self.high = self.high.checked_add(u64::from(carry))?;
		self.low = low;
		Some(())
	}

	/// `None` below zero, leaving `self` unchanged.
	#[must_use]
	pub fn sub(&mut self, x: u128) -> Option<()> {
		let (low, borrow) = self.low.overflowing_sub(x);
		self.high = self.high.checked_sub(u64::from(borrow))?;
		self.low = low;
		Some(())
	}
}

/// Splits a voter's `stake` across the winners it approves, as upstream's
/// backing step: an edge's load is its winner's score minus the score of the
/// voter's previous winner, its weight `⌊stake · edge load / voter load⌋`,
/// zero weights are dropped and the rest normalised to `stake`. If that fails,
/// the voter backs nobody: its edges never sum above its stake.
///
/// `approved` holds `(target, round)` in vote order; `score` gives a round's
/// winning score. Returns `(target, weight)` in vote order.
pub fn distribute(
	stake: VoteWeight,
	approved: &[(u16, u32)],
	score: impl Fn(u32) -> ExtendedBalance,
) -> Vec<(u16, ExtendedBalance)> {
	let mut by_round: Vec<(u32, usize)> = approved
		.iter()
		.enumerate()
		.map(|(i, &(_, round))| (round, i))
		.collect();
	by_round.sort_unstable();
	let Some(&(last, _)) = by_round.last() else {
		return Vec::new();
	};
	let voter_load = score(last);

	let mut edge_loads = alloc::vec![0; approved.len()];
	let mut previous = 0;
	for &(round, i) in &by_round {
		let s = score(round);
		if let Some(load) = edge_loads.get_mut(i) {
			*load = s.saturating_sub(previous);
		}
		previous = s;
	}

	let stake = ExtendedBalance::from(stake);
	let mut assignment = StakedAssignment {
		who: 0,
		distribution: approved
			.iter()
			.zip(edge_loads)
			.map(|(&(target, _), load)| (target, mul_div(stake, load, voter_load)))
			.filter(|&(_, weight)| weight > 0)
			.collect(),
	};
	if assignment.try_normalize(stake).is_err() {
		// Upstream fails the election here. It takes a winner scoring far below
		// an earlier one, which sequential Phragmén never does beyond rounding.
		log::error!(target: crate::LOG_TARGET, "normalising a voter's stake failed");
		return Vec::new();
	}
	assignment.distribution
}
