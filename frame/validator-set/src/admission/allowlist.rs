//! The allowlist: the accounts governance admits while the mode is
//! `Permissioned`.

use crate::{
	ApprovedValidators, Config, Error, Event, LastAuthorVersion, OnValidatorRemoved, Pallet,
	ValidatorPrerequisites,
};
use frame_support::{dispatch::DispatchResult, ensure};

impl<T: Config> Pallet<T> {
	/// Admits `validator`: not banned, with session keys already registered (or
	/// it would hold a slot without authoring), and not already in the list.
	pub(crate) fn add_to_approved(validator: T::AccountId) -> DispatchResult {
		ensure!(!Self::is_banned(&validator), Error::<T>::Banned);
		ensure!(
			T::Prerequisites::has_session_keys(&validator),
			Error::<T>::NoSessionKeys
		);
		ApprovedValidators::<T>::try_mutate(|validators| {
			ensure!(
				!validators.contains(&validator),
				Error::<T>::AlreadyValidator
			);
			validators
				.try_push(validator.clone())
				.map_err(|_| Error::<T>::TooManyValidators)
		})?;
		Self::deposit_event(Event::ValidatorAdded { validator });
		Ok(())
	}

	/// Drops `validator` from the list, and its declared version with it,
	/// notifies the removal hook and emits `ValidatorRemoved`. Fails if the
	/// account is not in the list.
	pub(crate) fn remove_from_approved(validator: &T::AccountId) -> DispatchResult {
		ApprovedValidators::<T>::try_mutate(|validators| -> DispatchResult {
			let pos = validators
				.iter()
				.position(|v| v == validator)
				.ok_or(Error::<T>::NotValidator)?;
			validators.remove(pos);
			Ok(())
		})?;
		LastAuthorVersion::<T>::remove(validator);

		T::OnValidatorRemoved::on_validator_removed(validator);
		Self::deposit_event(Event::ValidatorRemoved {
			validator: validator.clone(),
		});
		Ok(())
	}
}
