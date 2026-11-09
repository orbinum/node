//! Stake to vote weight, for the election and the voter list.
//!
//! Vote weights are `u64` and ORB has 18 decimals, so the supply does not fit and
//! stakes are divided by a factor. The factor is a constant, 10^9: a stake's
//! weight never depends on the issuance, so staking's snapshot (taken at one
//! issuance) and its exposures (converted back at a later one) always agree, and
//! a stake converts back exactly to 10^-9 ORB, rounded down. A single stake
//! saturates above `u64::MAX` · 10^9 planck, some 18.4 B ORB.
//!
//! Upstream's `U128CurrencyToVote` divides by `issuance / u64::MAX`, which leaves
//! a remainder on almost every stake and moves with the issuance.

use sp_runtime::traits::SaturatedConversion;
use sp_staking::currency_to_vote::CurrencyToVote;

pub struct DecimalCurrencyToVote;

/// Planck per unit of vote weight.
pub const VOTE_FACTOR: u128 = 1_000_000_000;

impl DecimalCurrencyToVote {
	/// [`VOTE_FACTOR`]. Upstream's pool benchmarks assume a weight equal to the
	/// stake, so a `runtime-benchmarks` build uses 1 while the issuance fits
	/// `u64`, as on the `benchmark` preset.
	pub fn factor(issuance: u128) -> u128 {
		if cfg!(feature = "runtime-benchmarks") && issuance <= u64::MAX as u128 {
			return 1;
		}
		VOTE_FACTOR
	}
}

impl CurrencyToVote<u128> for DecimalCurrencyToVote {
	fn to_vote(value: u128, issuance: u128) -> u64 {
		(value / Self::factor(issuance)).saturated_into()
	}

	fn to_currency(value: u128, issuance: u128) -> u128 {
		value.saturating_mul(Self::factor(issuance))
	}

	/// Whether a stake could exceed what `u64::MAX` votes hold.
	fn will_downscale(issuance: u128) -> Option<bool> {
		Some(issuance > (u64::MAX as u128).saturating_mul(Self::factor(issuance)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitives::constants::ORB;

	const BILLION_ORB: u128 = 1_000_000_000 * ORB;
	/// The most a stake converts without saturating.
	const CEILING: u128 = u64::MAX as u128 * VOTE_FACTOR;

	/// The issuances a factor tied to the issuance would step at.
	fn issuances() -> [u128; 6] {
		[
			BILLION_ORB,
			2 * BILLION_ORB,
			u64::MAX as u128 * 10u128.pow(8),
			u64::MAX as u128 * 10u128.pow(8) + 1,
			CEILING + 1,
			u128::MAX,
		]
	}

	#[test]
	fn the_factor_does_not_depend_on_the_issuance() {
		for issuance in issuances() {
			assert_eq!(DecimalCurrencyToVote::factor(issuance), VOTE_FACTOR);
			assert_eq!(
				DecimalCurrencyToVote::to_vote(1_000 * ORB, issuance),
				1_000_000_000_000
			);
		}
	}

	#[test]
	fn a_stake_round_trips_to_a_billionth_of_an_orb() {
		for stake in [1_000 * ORB, 10 * ORB, ORB / 3, 123_456_789_987_654_321] {
			for issuance in issuances() {
				let vote = DecimalCurrencyToVote::to_vote(stake, issuance);
				let back = DecimalCurrencyToVote::to_currency(vote.into(), issuance);
				assert!(back <= stake && stake - back < VOTE_FACTOR, "{stake}");
			}
		}
		// Upstream's factor loses part of a whole-ORB stake.
		use sp_staking::currency_to_vote::U128CurrencyToVote;
		let vote = U128CurrencyToVote::to_vote(1_000 * ORB, BILLION_ORB);
		assert!(U128CurrencyToVote::to_currency(vote.into(), BILLION_ORB) < 1_000 * ORB);
	}

	#[test]
	fn a_stake_below_one_vote_unit_weighs_nothing() {
		assert_eq!(
			DecimalCurrencyToVote::to_vote(VOTE_FACTOR - 1, BILLION_ORB),
			0
		);
		assert_eq!(DecimalCurrencyToVote::to_vote(VOTE_FACTOR, BILLION_ORB), 1);
	}

	/// Past `u64::MAX` votes a stake saturates, whatever the issuance.
	#[test]
	fn a_stake_past_the_ceiling_saturates() {
		assert_eq!(
			DecimalCurrencyToVote::to_vote(CEILING, BILLION_ORB),
			u64::MAX
		);
		assert_eq!(
			DecimalCurrencyToVote::to_vote(u128::MAX, BILLION_ORB),
			u64::MAX
		);
		assert_eq!(
			DecimalCurrencyToVote::to_currency(u64::MAX.into(), BILLION_ORB),
			CEILING
		);
		assert_eq!(
			DecimalCurrencyToVote::to_currency(u128::MAX, BILLION_ORB),
			u128::MAX
		);
	}

	#[test]
	fn downscaling_is_signalled_once_a_stake_could_saturate() {
		assert_eq!(
			DecimalCurrencyToVote::will_downscale(BILLION_ORB),
			Some(false)
		);
		assert_eq!(DecimalCurrencyToVote::will_downscale(CEILING), Some(false));
		assert_eq!(
			DecimalCurrencyToVote::will_downscale(CEILING + 1),
			Some(true)
		);
	}
}
