//! Who may be a validator candidate: the admission mode, the allowlist and bans.
//!
//! This pallet answers *may this account validate*; it does not pick the active
//! set. The runtime combines [`Admission::check`] with what only staking knows
//! (self-bond, commission) and applies the result twice: when a candidacy is
//! submitted and when each election takes its snapshot.
//!
//! - this module: reading the rules ([`Admission`]);
//! - [`allowlist`]: who governance admits in `Permissioned` mode;
//! - [`bans`]: who may not validate in either mode, and until when.

pub mod allowlist;
pub mod bans;

use crate::{
	ApprovedValidators, Bans, Config, Mode, Pallet, ValidatorPrerequisites,
	types::{AdmissionMode, Inadmissible},
};
use alloc::collections::BTreeSet;
use frame_support::traits::Contains;
use frame_system::pallet_prelude::BlockNumberFor;

/// The admission rules at one block, read once so an election snapshot does not
/// decode the allowlist per candidate.
pub struct Admission<T: Config> {
	mode: AdmissionMode,
	approved: BTreeSet<T::AccountId>,
	now: BlockNumberFor<T>,
}

impl<T: Config> Admission<T> {
	pub fn mode(&self) -> AdmissionMode {
		self.mode
	}

	/// Whether `who` may validate. Bans and session keys are read per account;
	/// the mode and the allowlist come from the snapshot.
	pub fn check(&self, who: &T::AccountId) -> Result<(), Inadmissible> {
		if Bans::<T>::get(who).is_some_and(|term| term.active_at(self.now)) {
			return Err(Inadmissible::Banned);
		}
		if self.mode == AdmissionMode::Permissioned && !self.approved.contains(who) {
			return Err(Inadmissible::NotApproved);
		}
		if !T::Prerequisites::has_session_keys(who) {
			return Err(Inadmissible::NoSessionKeys);
		}
		Ok(())
	}
}

impl<T: Config> Pallet<T> {
	/// The admission rules in force at the current block.
	pub fn admission() -> Admission<T> {
		Admission {
			mode: Mode::<T>::get(),
			approved: ApprovedValidators::<T>::get().into_iter().collect(),
			now: frame_system::Pallet::<T>::block_number(),
		}
	}

	/// Whether `who` is under a ban at the current block.
	pub fn is_banned(who: &T::AccountId) -> bool {
		let now = frame_system::Pallet::<T>::block_number();
		Bans::<T>::get(who).is_some_and(|term| term.active_at(now))
	}
}

impl<T: Config> Contains<T::AccountId> for Pallet<T> {
	/// Whether `who` may validate now. For one-off checks; read
	/// [`Pallet::admission`] once when checking many accounts.
	fn contains(who: &T::AccountId) -> bool {
		Self::admission().check(who).is_ok()
	}
}
