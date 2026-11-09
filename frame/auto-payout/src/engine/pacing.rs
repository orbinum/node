//! How much of a block the pallet may spend. Pure functions over the limits,
//! the era's progress and the block's weight.

use crate::types::PayoutLimits;
use frame_support::weights::Weight;

/// Work an era should have paid by `elapsed` blocks: `work` spread evenly over
/// `window` blocks.
pub fn expected(work: u64, elapsed: u64, window: u64) -> u64 {
	if window == 0 {
		return work;
	}
	let elapsed = elapsed.min(window);
	(u128::from(work) * u128::from(elapsed) / u128::from(window)) as u64
}

/// Whether an era that has paid `done` of `work` is behind its schedule. An era
/// still being paid once its window is over is behind whatever its progress
/// says: progress is priced with the weights of the block that paid each page,
/// and a weight change mid-era can bring it to `work` with pages left.
pub fn is_behind(done: u64, work: u64, elapsed: u64, window: u64) -> bool {
	done < expected(work, elapsed, window) || elapsed >= window
}

/// The share `on_initialize` spends: nothing on heavy blocks or while on
/// schedule, `catch_up` while more than one era waits, `floor` while behind.
pub fn guaranteed(
	limits: &PayoutLimits,
	block: Weight,
	waiting_eras: u32,
	behind: bool,
	heavy: bool,
) -> Weight {
	if heavy || waiting_eras == 0 {
		Weight::zero()
	} else if waiting_eras > 1 {
		limits.catch_up * block
	} else if behind {
		limits.floor * block
	} else {
		Weight::zero()
	}
}

/// The share `on_idle` spends: its cap, or what the block has left.
pub fn idle(limits: &PayoutLimits, block: Weight, remaining: Weight) -> Weight {
	(limits.idle * block).min(remaining)
}
