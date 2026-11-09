//! Each block's budget: what `on_initialize` must spend to keep the schedule,
//! and what `on_idle` may take from the weight transactions left.

use crate::{Config, Current, Event, Limits, Pallet, Paused, Queue, pacing, types::EraPayouts};
use frame_support::{pallet_prelude::*, traits::Get, weights::Weight};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::UniqueSaturatedInto;

impl<T: Config> Pallet<T> {
	/// Pays only what the schedule requires: nothing while on time, `floor` when
	/// behind, `catch_up` while eras pile up. Never on heavy blocks.
	pub(crate) fn on_initialize_block(now: BlockNumberFor<T>) -> Weight {
		let db = Self::db();
		let mut used = db.reads(1).saturating_add(Self::note_active_era());
		if Paused::<T>::get() || T::Payouts::is_heavy_block(now) {
			return used;
		}

		used.saturating_accrue(db.reads(3));
		let mut current = Current::<T>::get();
		let queued = Queue::<T>::decode_len().unwrap_or(0) as u32;
		let waiting = queued.saturating_add(u32::from(current.is_some()));
		if waiting == 0 {
			return used;
		}

		let window = T::PaymentWindow::get().unique_saturated_into();
		// An era waiting to start is behind: on a full chain `on_idle` would
		// never start it.
		let mut behind = current.is_none();
		if let Some(state) = current.as_mut() {
			behind = pacing::is_behind(
				state.done,
				state.work,
				Self::elapsed(now, state.started),
				window,
			);
			if behind && !state.reported_behind {
				state.reported_behind = true;
				Current::<T>::put(&*state);
				used.saturating_accrue(db.writes(1));
				Self::deposit_event(Event::BehindSchedule { era: state.era });
			}
		}

		let share = pacing::guaranteed(
			&Limits::<T>::get(),
			Self::max_block(),
			waiting,
			behind,
			false,
		);
		// A floor set before a weight change may no longer fit a step; the
		// defaults always do (`integrity_test`), so this stays within the caps.
		let share = if share.is_zero() {
			share
		} else {
			share.max(Self::largest_step())
		};
		let budget = share.saturating_sub(used);
		if budget.is_zero() {
			return used;
		}
		used.saturating_add(Self::spend(now, budget, current))
	}

	/// Pays from what the block left unused, up to the idle share. Never on
	/// heavy blocks: their declared weight may understate what they run.
	pub(crate) fn on_idle_block(now: BlockNumberFor<T>, remaining: Weight) -> Weight {
		let db = Self::db();
		if remaining.any_lt(db.reads_writes(4, 2)) {
			return Weight::zero();
		}
		let mut used = db.reads(1);
		if Paused::<T>::get() || T::Payouts::is_heavy_block(now) {
			return used;
		}
		used.saturating_accrue(db.reads(3));
		let current = Current::<T>::get();
		if current.is_none() && Queue::<T>::decode_len().unwrap_or(0) == 0 {
			return used;
		}
		let share = pacing::idle(&Limits::<T>::get(), Self::max_block(), remaining);
		let budget = share.saturating_sub(used);
		used.saturating_add(Self::spend(now, budget, current))
	}
}
