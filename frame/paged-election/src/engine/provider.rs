// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The [`ElectionProvider`] interface, as `pallet-staking-async` drives it:
//! `start` when it plans an era, `status` each block until ready, then
//! `elect(page)` once per block from the most significant page down to 0.

use crate::{Config, CurrentPhase, ElectionError, Event, Meta, Pallet, Phase};
use frame_election_provider_support::{BoundedSupportsOf, ElectionProvider, PageIndex};
use frame_support::weights::Weight;
use frame_system::pallet_prelude::BlockNumberFor;

impl<T: Config> ElectionProvider for Pallet<T> {
	type AccountId = T::AccountId;
	type BlockNumber = BlockNumberFor<T>;
	type Error = ElectionError;
	type MaxWinnersPerPage = T::MaxWinnersPerPage;
	type MaxBackersPerWinner = T::MaxBackersPerWinner;
	type MaxBackersPerWinnerFinal = T::MaxBackersPerWinnerFinal;
	type Pages = T::Pages;
	type DataProvider = T::DataProvider;

	/// A page's supports once done; page 0 also clears the election, failed or
	/// not, and any other page counts as fetched. While computing, errors and
	/// changes nothing; after a failure, errors: staking then records the page
	/// as failed and keeps its validators.
	fn elect(page: PageIndex) -> Result<BoundedSupportsOf<Self>, Self::Error> {
		if page > Self::msp() {
			return Err(ElectionError::InvalidPage);
		}
		let result = match CurrentPhase::<T>::get() {
			Phase::Off => return Err(ElectionError::NotOngoing),
			phase if phase.is_computing() => return Err(ElectionError::NotReady),
			Phase::Failed(reason) => Err(ElectionError::Failed(reason)),
			_ => Self::export(page),
		};
		if page == 0 {
			Self::clear();
		} else {
			Meta::<T>::mutate(|meta| {
				let meta = meta.get_or_insert_with(Default::default);
				meta.fetched = meta.fetched.saturating_add(1);
			});
		}
		result
	}

	/// Arms an election; refuses while one runs or waits to be fetched.
	fn start() -> Result<(), Self::Error> {
		if CurrentPhase::<T>::get() != Phase::Off {
			return Err(ElectionError::Ongoing);
		}
		Meta::<T>::put(crate::ElectionMeta {
			started: frame_system::Pallet::<T>::block_number(),
			..Default::default()
		});
		CurrentPhase::<T>::put(Phase::Targets);
		Self::deposit_event(Event::ElectionStarted);
		Ok(())
	}

	/// See [`Pallet::duration_bound`].
	fn duration() -> Self::BlockNumber {
		Self::duration_bound().into()
	}

	/// `Err` when idle, `Ok(None)` while computing, else ready with the weight
	/// of fetching a page (failed elections included: their pages error).
	fn status() -> Result<Option<Weight>, ()> {
		match CurrentPhase::<T>::get() {
			Phase::Off => Err(()),
			Phase::Done | Phase::Failed(_) => Ok(Some(Self::export_weight())),
			_ => Ok(None),
		}
	}

	/// Finishes the election now, whatever it costs.
	#[cfg(any(feature = "runtime-benchmarks", feature = "std"))]
	fn asap() {
		let now = frame_system::Pallet::<T>::block_number();
		let mut meter = frame_support::weights::WeightMeter::new();
		let mut phase = CurrentPhase::<T>::get();
		while let Some(next) = Self::step(now, phase, &mut meter) {
			phase = next;
		}
	}
}
