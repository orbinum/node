// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Noticing closed eras: queueing the ones that closed, expiring the ones that
//! left staking's history unpaid.

use crate::{Config, Current, Event, LastActiveEra, Pallet, Queue, types::EraPayouts};
use frame_support::{traits::Get, weights::Weight};

impl<T: Config> Pallet<T> {
	/// Notes staking's active era; when it moved on, queues the eras that closed
	/// and drops those staking no longer pays.
	pub(super) fn note_active_era() -> Weight {
		let db = Self::db();
		let mut weight = db.reads(2);
		let Some(active) = T::Payouts::active_era() else {
			return weight;
		};
		let last = LastActiveEra::<T>::get();
		if last.is_some_and(|last| last >= active) {
			return weight;
		}
		LastActiveEra::<T>::put(active);
		weight.saturating_accrue(db.writes(1));
		// First sight (the pallet was just added): nothing before is known unpaid.
		let Some(first) = last else {
			return weight;
		};

		// Staking pays from its planned era's history: one era shorter while the
		// next era is planned.
		let planned = T::Payouts::planned_era().unwrap_or(active).max(active);
		let oldest = Self::oldest_payable(planned);
		weight.saturating_accrue(db.reads_writes(3, 2));
		let mut first_queued = None;
		Queue::<T>::mutate(|queue| {
			queue.retain(|&era| {
				let keep = era >= oldest;
				if !keep {
					Self::deposit_event(Event::EraExpired { era });
				}
				keep
			});
			// Eras that closed already out of history were never payable. Staking
			// moves one era at a time, so this range is short; the cap only
			// guards against a jump.
			let gone = oldest.min(first.saturating_add(T::MaxQueuedEras::get()));
			for era in first..gone {
				Self::deposit_event(Event::EraExpired { era });
			}
			for era in first.max(oldest)..active {
				if queue.contains(&era) {
					continue;
				}
				if queue.try_push(era).is_ok() {
					Self::deposit_event(Event::EraQueued { era });
				} else {
					Self::deposit_event(Event::EraExpired { era });
				}
			}
			first_queued = queue.first().copied();
		});
		let paying = match Current::<T>::get() {
			Some(state) if state.era < oldest => {
				Current::<T>::kill();
				Self::deposit_event(Event::EraExpired { era: state.era });
				None
			}
			state => state.map(|state| state.era),
		};

		weight.saturating_accrue(Self::guard_expiry(planned, paying.or(first_queued)));
		weight
	}
}
