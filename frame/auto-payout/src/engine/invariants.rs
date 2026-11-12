// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! What must hold after every block: checked by `try_state` and by the tests.

use crate::{Config, Current, LastActiveEra, Limits, Pallet, Paused, Queue, types::EraPayouts};
use frame_support::pallet_prelude::*;

impl<T: Config> Pallet<T> {
	pub(crate) fn do_try_state() -> Result<(), sp_runtime::TryRuntimeError> {
		Self::check_decodes()?;
		let queue = Queue::<T>::get();
		ensure!(
			queue.windows(2).all(|w| w[0] < w[1]),
			"queue must be strictly ascending"
		);
		if let Some(last) = LastActiveEra::<T>::get() {
			ensure!(
				queue.iter().all(|&era| era < last),
				"queued eras must be closed"
			);
		}
		if let Some(state) = Current::<T>::get() {
			ensure!(
				queue.first().is_none_or(|&next| state.era < next),
				"the era being paid must be older than the queue"
			);
			ensure!(state.done <= state.work, "progress beyond the era's work");
			ensure!(!state.is_done(), "a paid era is never kept");
			ensure!(
				state.validators.iter().all(|v| v.pages > 0),
				"a validator without pages is never kept"
			);
			if let Some(last) = LastActiveEra::<T>::get() {
				ensure!(state.era < last, "the era being paid must be closed");
			}
			if let Some((validator, page)) = state.next() {
				ensure!(page < validator.pages, "page beyond the validator's pages");
			}
		}
		ensure!(
			queue.len() as u32 <= T::Payouts::history_depth(),
			"more eras queued than staking keeps"
		);
		// The caps and their order only: a floor set before a weight change may
		// no longer fit a step, which the hooks tolerate.
		Limits::<T>::get()
			.check(Self::max_block(), Weight::zero())
			.map_err(|_| "limits are invalid")?;
		Ok(())
	}

	/// Every stored value decodes. A read that fails to decode yields the
	/// default (an empty queue, no era being paid), which would drop eras
	/// silently: e.g. after a lower `MaxQueuedEras` or `MaxValidators`.
	fn check_decodes() -> Result<(), sp_runtime::TryRuntimeError> {
		ensure!(
			!Queue::<T>::exists() || Queue::<T>::try_get().is_ok(),
			"the queue does not decode"
		);
		ensure!(
			Current::<T>::exists() == Current::<T>::get().is_some(),
			"the era being paid does not decode"
		);
		ensure!(
			LastActiveEra::<T>::exists() == LastActiveEra::<T>::get().is_some(),
			"the last active era does not decode"
		);
		ensure!(
			!Limits::<T>::exists() || Limits::<T>::try_get().is_ok(),
			"the limits do not decode"
		);
		ensure!(
			!Paused::<T>::exists() || Paused::<T>::try_get().is_ok(),
			"the pause flag does not decode"
		);
		Ok(())
	}
}
