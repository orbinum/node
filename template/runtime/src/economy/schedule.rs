// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The yearly issuance that pays stakers, prorated per era: the 300M ORB staking
//! allocation over ten years (45M in year 1 down to 20M in year 10), then 20M a
//! year.

use crate::{
	primitives::constants::{DAY_MS, ORB, YEAR_MS},
	Balance,
};

const MILLION_ORB: Balance = 1_000_000 * ORB;

/// The tokenomics' staking allocation, issued over years 1 to 10.
#[cfg(test)]
pub const STAKING_ALLOCATION: Balance = 300 * MILLION_ORB;

/// Issuance for stakers in years 1 to 10, summing to [`STAKING_ALLOCATION`].
/// Later years repeat the last value: 20M ORB a year.
pub const ANNUAL_ISSUANCE: [Balance; 10] = [
	45 * MILLION_ORB,
	40 * MILLION_ORB,
	36 * MILLION_ORB,
	33 * MILLION_ORB,
	30 * MILLION_ORB,
	27 * MILLION_ORB,
	25 * MILLION_ORB,
	23 * MILLION_ORB,
	21 * MILLION_ORB,
	20 * MILLION_ORB,
];

/// Eras in a year at one era a day. Years count from staking's first paid era.
pub const ERAS_PER_YEAR: u32 = 365;

/// The longest era duration that is paid for. An era stretched by a stall pays
/// at most this, so a long halt does not mint a year's issuance at once.
pub const MAX_PAID_ERA_MS: u64 = 2 * DAY_MS;

/// A yearly issuance schedule.
pub trait InflationSchedule {
	/// Issuance for the 0-based `year`.
	fn annual(year: u32) -> Balance;
}

/// [`ANNUAL_ISSUANCE`].
pub struct TokenomicsSchedule;

impl InflationSchedule for TokenomicsSchedule {
	fn annual(year: u32) -> Balance {
		let last = ANNUAL_ISSUANCE.len() - 1;
		ANNUAL_ISSUANCE[(year as usize).min(last)]
	}
}

/// What an era of `duration_ms` in `year` issues under `S`.
pub fn era_issuance<S: InflationSchedule>(year: u32, duration_ms: u64) -> Balance {
	let paid_ms = duration_ms.min(MAX_PAID_ERA_MS) as Balance;
	// At most 45M ORB × 2 days in ms ≈ 8e33, well inside u128.
	S::annual(year).saturating_mul(paid_ms) / YEAR_MS as Balance
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ten_years_issue_the_staking_allocation() {
		assert_eq!(ANNUAL_ISSUANCE.iter().sum::<Balance>(), STAKING_ALLOCATION);
	}

	#[test]
	fn year_one_day_pays_a_365th() {
		assert_eq!(
			era_issuance::<TokenomicsSchedule>(0, DAY_MS),
			45 * MILLION_ORB / 365
		);
	}

	#[test]
	fn later_years_follow_the_table_then_repeat_the_last() {
		assert_eq!(TokenomicsSchedule::annual(1), 40 * MILLION_ORB);
		assert_eq!(TokenomicsSchedule::annual(9), 20 * MILLION_ORB);
		assert_eq!(TokenomicsSchedule::annual(10), 20 * MILLION_ORB);
		assert_eq!(TokenomicsSchedule::annual(u32::MAX), 20 * MILLION_ORB);
	}

	#[test]
	fn zero_duration_pays_nothing() {
		assert_eq!(era_issuance::<TokenomicsSchedule>(0, 0), 0);
	}

	#[test]
	fn a_stalled_era_is_capped() {
		assert_eq!(
			era_issuance::<TokenomicsSchedule>(0, 10 * DAY_MS),
			era_issuance::<TokenomicsSchedule>(0, MAX_PAID_ERA_MS)
		);
		assert_eq!(
			era_issuance::<TokenomicsSchedule>(0, u64::MAX),
			era_issuance::<TokenomicsSchedule>(0, MAX_PAID_ERA_MS)
		);
	}
}
