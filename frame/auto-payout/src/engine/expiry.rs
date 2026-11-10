//! The expiry watchdog: an unpaid era must not leave staking's history quietly.

use crate::{
	Config, Current, Event, Pallet, Paused, Queue,
	types::{EraIndex, EraPayouts},
};
use frame_support::{traits::Get, weights::Weight};

impl<T: Config> Pallet<T> {
	/// With `planned` the latest era staking planned, checks `oldest_unpaid`:
	/// within [`Config::ExpiryMargin`] eras of leaving history it is reported
	/// while there is time, and a pause lifted so it is paid. Only a call filter
	/// can still hold it then.
	pub(super) fn guard_expiry(planned: EraIndex, oldest_unpaid: Option<EraIndex>) -> Weight {
		let Some(era) = oldest_unpaid else {
			return Weight::zero();
		};
		let eras_left = Self::eras_left(era, planned);
		if eras_left > T::ExpiryMargin::get() {
			return Weight::zero();
		}
		let db = Self::db();
		Self::deposit_event(Event::ExpiryAtRisk { era, eras_left });
		if !Paused::<T>::get() {
			return db.reads(1);
		}
		Paused::<T>::kill();
		Self::deposit_event(Event::ResumedToAvoidExpiry { era });
		db.reads_writes(1, 1)
	}

	/// Eras `era` has left in staking's history once `planned` is planned.
	fn eras_left(era: EraIndex, planned: EraIndex) -> EraIndex {
		era.saturating_add(T::Payouts::history_depth())
			.saturating_sub(planned)
	}

	/// Whether the oldest unpaid era is within [`Config::ExpiryMargin`] eras of
	/// leaving staking's history: a pause then would hold it until it expires.
	pub(crate) fn expiry_is_near() -> bool {
		let oldest_unpaid = Current::<T>::get()
			.map(|state| state.era)
			.or_else(|| Queue::<T>::get().first().copied());
		let Some(era) = oldest_unpaid else {
			return false;
		};
		let active = T::Payouts::active_era().unwrap_or_default();
		let planned = T::Payouts::planned_era().unwrap_or(active).max(active);
		Self::eras_left(era, planned) <= T::ExpiryMargin::get()
	}
}
