//! The budget rules, as pure functions.

use crate::{LimitsError, PayoutLimits, pacing::*};
use frame_support::weights::Weight;
use sp_runtime::Perbill;

const BLOCK: Weight = Weight::from_parts(1_000_000_000, u64::MAX);

fn limits(floor: u32, catch_up: u32, idle: u32) -> PayoutLimits {
	PayoutLimits {
		floor: Perbill::from_percent(floor),
		catch_up: Perbill::from_percent(catch_up),
		idle: Perbill::from_percent(idle),
	}
}

#[test]
fn expected_spreads_work_evenly_over_the_window() {
	assert_eq!(expected(1_000, 0, 100), 0);
	assert_eq!(expected(1_000, 25, 100), 250);
	assert_eq!(expected(1_000, 100, 100), 1_000);
	assert_eq!(expected(1_000, 500, 100), 1_000, "clamped at the window");
	assert_eq!(expected(1_000, 3, 0), 1_000, "no window: all of it now");
	assert_eq!(expected(u64::MAX, 50, 100), u64::MAX / 2, "no overflow");
}

#[test]
fn behind_means_less_done_than_expected() {
	assert!(!is_behind(250, 1_000, 25, 100));
	assert!(is_behind(249, 1_000, 25, 100));
	assert!(!is_behind(0, 1_000, 0, 100), "a fresh era is on time");
}

#[test]
fn guaranteed_share_follows_the_schedule() {
	let l = limits(2, 4, 10);
	let pct = |n: u64| Weight::from_parts(n * 10_000_000, n * (u64::MAX / 100));
	assert_eq!(
		guaranteed(&l, BLOCK, 0, true, false),
		Weight::zero(),
		"nothing waits"
	);
	assert_eq!(
		guaranteed(&l, BLOCK, 1, false, false),
		Weight::zero(),
		"on schedule"
	);
	assert_eq!(
		guaranteed(&l, BLOCK, 1, true, false).ref_time(),
		pct(2).ref_time()
	);
	assert_eq!(
		guaranteed(&l, BLOCK, 2, false, false).ref_time(),
		pct(4).ref_time()
	);
	assert_eq!(
		guaranteed(&l, BLOCK, 3, true, true),
		Weight::zero(),
		"heavy block"
	);
}

#[test]
fn idle_share_is_capped_by_what_is_left() {
	let l = limits(2, 4, 10);
	assert_eq!(idle(&l, BLOCK, BLOCK).ref_time(), 100_000_000);
	let little = Weight::from_parts(5, 5);
	assert_eq!(idle(&l, BLOCK, little), little);
}

#[test]
fn limits_are_checked_against_caps_and_the_largest_step() {
	let step = Weight::from_parts(15_000_000, 0);
	assert_eq!(limits(2, 4, 10).check(BLOCK, step), Ok(()));
	assert_eq!(
		limits(11, 11, 10).check(BLOCK, step),
		Err(LimitsError::AboveCap)
	);
	assert_eq!(
		limits(2, 11, 10).check(BLOCK, step),
		Err(LimitsError::AboveCap)
	);
	assert_eq!(
		limits(2, 4, 26).check(BLOCK, step),
		Err(LimitsError::AboveCap)
	);
	assert_eq!(
		limits(3, 2, 10).check(BLOCK, step),
		Err(LimitsError::CatchUpBelowFloor)
	);
	assert_eq!(
		limits(1, 4, 10).check(BLOCK, step),
		Err(LimitsError::FloorBelowStep)
	);
}

/// Past its window an era still being paid is behind, even when its progress
/// (priced with the weights at the time) reached its work: a weight rise
/// mid-era must not leave its last pages waiting for the next era.
#[test]
fn an_era_past_its_window_is_behind_whatever_its_progress() {
	assert!(!is_behind(100, 100, 99, 100));
	assert!(is_behind(100, 100, 100, 100));
	assert!(is_behind(100, 100, 150, 100));
}
