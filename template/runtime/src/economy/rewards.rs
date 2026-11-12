// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! What an era pays stakers, and where it comes from.
//!
//! Staking (`pallet-staking-async`, minting mode) mints an era's reward when
//! stakers claim it. A source that already holds the funds (the fee pool, or a
//! pre-funded pot) is burned when the era closes, so the claims re-mint what was
//! burned: at most all of it, less the shares nobody can be paid (a validator
//! with no points or no exposure) and rounding. Pure inflation burns nothing.
//!
//! The inflation year counts eras from the first one that pays (era 1: era 0 has
//! no exposures), [`ERAS_PER_YEAR`] to a year, not time. An era lasts at least a
//! day: its set is handed over at a fixed session, forced or not. Halts and missed
//! slots make it longer, and each era mints for the time it lasted, so a year of
//! longer eras turns later than the calendar and mints more than the year's rate.
//!
//! The era's duration is measured from the timestamp the session side reports
//! when the era's set became active to the one of the next set.
//!
//! To pay rewards from a pre-funded pot instead of inflation, add a source that
//! drains `min(schedule, pot)` from the pot (a capped [`DrainAccount`]) and swap
//! it for [`Inflation`] in the runtime's era payout.

use super::schedule::{era_issuance, InflationSchedule, ERAS_PER_YEAR};
use crate::{AccountId, Balance};
use core::marker::PhantomData;
use frame_support::traits::{
	fungible::Mutate,
	tokens::{Fortitude, Precision, Preservation},
	Get, TypedGet,
};
use sp_staking::EraIndex;

/// Something that contributes to an era's staker reward.
pub trait EraRewardSource {
	/// The amount it contributes for `era`, which lasted `duration_ms`. Called
	/// once per era, when it closes; a source holding funds gives them up here.
	fn take(era: EraIndex, duration_ms: u64) -> Balance;
}

/// Two sources, summed. Nest pairs for more.
impl<A: EraRewardSource, B: EraRewardSource> EraRewardSource for (A, B) {
	fn take(era: EraIndex, duration_ms: u64) -> Balance {
		A::take(era, duration_ms).saturating_add(B::take(era, duration_ms))
	}
}

/// New issuance on schedule `S`.
pub struct Inflation<S>(PhantomData<S>);

impl<S: InflationSchedule> EraRewardSource for Inflation<S> {
	fn take(era: EraIndex, duration_ms: u64) -> Balance {
		era_issuance::<S>(era.saturating_sub(1) / ERAS_PER_YEAR, duration_ms)
	}
}

/// Everything account `A` holds in currency `F`, e.g. the fees collected
/// during the era.
pub struct DrainAccount<A, F>(PhantomData<(A, F)>);

impl<A, F> EraRewardSource for DrainAccount<A, F>
where
	A: TypedGet<Type = AccountId>,
	F: Mutate<AccountId, Balance = Balance>,
{
	fn take(_era: EraIndex, _duration_ms: u64) -> Balance {
		let who = A::get();
		let available = F::reducible_balance(&who, Preservation::Expendable, Fortitude::Polite);
		F::burn_from(
			&who,
			available,
			Preservation::Expendable,
			Precision::BestEffort,
			Fortitude::Polite,
		)
		.unwrap_or_else(|e| {
			log::error!(target: "runtime::economy", "cannot drain the era reward source: {e:?}");
			0
		})
	}
}

/// `pallet_staking_async::Config::EraPayout`: the sum of `Sources` for the era
/// `Era` names (the one closing), all of it to stakers.
///
/// An era without exposures (era 0, at genesis or after the upgrade that added
/// staking) pays nothing and takes nothing, so collected fees roll into the
/// first paid era.
pub struct RewardSources<Sources, Era>(PhantomData<(Sources, Era)>);

impl<Sources, Era> sp_staking::EraPayout<Balance> for RewardSources<Sources, Era>
where
	Sources: EraRewardSource,
	Era: Get<EraIndex>,
{
	fn era_payout(
		total_staked: Balance,
		_total_issuance: Balance,
		era_duration_millis: u64,
	) -> (Balance, Balance) {
		if total_staked == 0 {
			return (0, 0);
		}
		(Sources::take(Era::get(), era_duration_millis), 0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		economy::schedule::{TokenomicsSchedule, STAKING_ALLOCATION},
		primitives::constants::DAY_MS,
	};

	type Scheduled = Inflation<TokenomicsSchedule>;

	#[test]
	fn inflation_years_count_from_the_first_paid_era() {
		let year = |y| era_issuance::<TokenomicsSchedule>(y, DAY_MS);
		assert_eq!(Scheduled::take(1, DAY_MS), year(0));
		assert_eq!(Scheduled::take(ERAS_PER_YEAR, DAY_MS), year(0));
		assert_eq!(Scheduled::take(ERAS_PER_YEAR + 1, DAY_MS), year(1));
		assert_eq!(Scheduled::take(10 * ERAS_PER_YEAR + 1, DAY_MS), year(10));
	}

	/// The first ten years of one-day eras, era 1 to era 3650, issue the staking
	/// allocation: never more, and under one unit per era less (rounding).
	#[test]
	fn ten_years_of_paid_eras_issue_the_allocation() {
		let eras = 10 * ERAS_PER_YEAR;
		let issued: Balance = (1..=eras).map(|era| Scheduled::take(era, DAY_MS)).sum();
		assert!(issued <= STAKING_ALLOCATION);
		assert!(STAKING_ALLOCATION - issued < eras as Balance);
	}
}
