//! Bans: who may not validate in either mode, and until when.

use crate::{BanTerm, Bans, Config, Error, Event, LastAuthorVersion, OnValidatorRemoved, Pallet};
use frame_support::dispatch::DispatchResult;
use frame_system::pallet_prelude::BlockNumberFor;

impl<T: Config> Pallet<T> {
	/// Ban `who` for `term` on behalf of the runtime, e.g. for a reported
	/// offence. Never shortens a ban already in force, and a term already over
	/// with no ban in force changes nothing. Costs at most
	/// [`WeightInfo::ban_validator`](crate::WeightInfo::ban_validator).
	pub fn ban_offender(who: &T::AccountId, term: BanTerm<BlockNumberFor<T>>) {
		let now = frame_system::Pallet::<T>::block_number();
		let term = match Bans::<T>::get(who).filter(|current| current.active_at(now)) {
			Some(current) => current.longest(term),
			None => term,
		};
		// An expired term would stop the account validating for nothing.
		if term.active_at(now) {
			Self::ban(who, term);
		}
	}

	/// Records `term` for `validator`, replacing any ban it has; stops it
	/// validating, drops its declared version (it no longer counts toward a
	/// version quorum) and emits `ValidatorBanned`.
	pub(crate) fn ban(validator: &T::AccountId, term: BanTerm<BlockNumberFor<T>>) {
		Bans::<T>::insert(validator, term);
		LastAuthorVersion::<T>::remove(validator);
		T::OnValidatorRemoved::on_validator_removed(validator);
		Self::deposit_event(Event::ValidatorBanned {
			validator: validator.clone(),
			term,
		});
	}

	/// Lifts `validator`'s ban, expired or not, and emits `ValidatorUnbanned`.
	pub(crate) fn lift_ban(validator: T::AccountId) -> DispatchResult {
		Bans::<T>::take(&validator).ok_or(Error::<T>::NotBanned)?;
		Self::deposit_event(Event::ValidatorUnbanned { validator });
		Ok(())
	}
}
