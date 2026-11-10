//! The hooks' work, one concern per module: noticing closed eras ([`queue`]),
//! guarding unpaid eras from expiry ([`expiry`]), deciding each block's budget
//! ([`hooks`]), paying pages within it ([`payment`]) and the invariants
//! (`invariants`, for `try_state` and tests). This module holds the cost model
//! they share.

mod expiry;
mod hooks;
#[cfg(any(feature = "try-runtime", test))]
mod invariants;
pub mod pacing;
mod payment;
mod queue;

use crate::{
	Config, Pallet,
	types::{EraIndex, EraPayouts, LimitsError, PayoutLimits},
};
use frame_support::{
	traits::Get,
	weights::{RuntimeDbWeight, Weight},
};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::{Saturating, UniqueSaturatedInto};

/// CPU of pricing one validator's pages when an era starts: three
/// `page_weight` calls and its entry in the era's state. An estimate, to be
/// replaced by a benchmark of starting the largest era.
pub(crate) const START_CPU_PER_VALIDATOR: Weight = Weight::from_parts(1_000_000, 0);

impl<T: Config> Pallet<T> {
	pub(super) fn db() -> RuntimeDbWeight {
		T::DbWeight::get()
	}

	pub(super) fn max_block() -> Weight {
		T::BlockWeights::get().max_block
	}

	/// Reading an era's validators and pricing their pages.
	pub(super) fn start_era_weight() -> Weight {
		let validators = u64::from(T::MaxValidators::get());
		Self::db()
			.reads(validators + 1)
			.saturating_add(START_CPU_PER_VALIDATOR.saturating_mul(validators))
	}

	/// Starting an era: reading the queue and the planned era, then
	/// [`Self::start_era_weight`].
	pub(crate) fn start_weight() -> Weight {
		Self::db().reads(2).saturating_add(Self::start_era_weight())
	}

	/// The oldest era staking still pays once it has planned `planned`.
	pub(super) fn oldest_payable(planned: EraIndex) -> EraIndex {
		planned.saturating_sub(T::Payouts::history_depth())
	}

	/// The most `on_initialize` spends on anything other than a step, plus the
	/// heaviest step: a full page or starting an era. `floor` must cover it.
	pub fn largest_step() -> Weight {
		let page = T::Payouts::page_weight(T::Payouts::page_size());
		let hook = Self::db().reads_writes(6, 1);
		let flush = Self::db().writes(2);
		page.max(Self::start_weight())
			.saturating_add(hook)
			.saturating_add(flush)
	}

	pub fn check_limits(limits: &PayoutLimits) -> Result<(), LimitsError> {
		limits.check(Self::max_block(), Self::largest_step())
	}

	pub(super) fn elapsed(now: BlockNumberFor<T>, started: BlockNumberFor<T>) -> u64 {
		now.saturating_sub(started).unique_saturated_into()
	}
}
