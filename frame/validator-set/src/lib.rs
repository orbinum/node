//! # Pallet Validator Set
//!
//! Governance-controlled allowlist of block producers for Orbinum. Candidate
//! selection happens off-chain; on-chain only records the decision.
//!
//! ## Onboarding Flow
//!
//! 1. The operator registers session keys on their own node (`session.setKeys`).
//!    The private key never leaves their machine, so this step cannot be done for them.
//! 2. `AddRemoveOrigin` (sudo / governance) calls
//!    [`add_validator`][Pallet::add_validator] with the operator's `AccountId`.
//!    The account joins the approved set and produces blocks from the next session.
//! 3. Once approved, the operator may register an EVM relay address via
//!    `relayer.register_relayer` (gated on membership of the approved set).
//!
//! ## Leaving
//!
//! Either [`remove_validator`][Pallet::remove_validator] (sudo) or
//! [`deregister_validator`][Pallet::deregister_validator] (the validator itself).
//! Both notify [`Config::OnValidatorRemoved`].
//!
//! ## Sudo Paths
//!
//! - [`add_validator`][Pallet::add_validator] — Add an operator to the approved set.
//! - [`remove_validator`][Pallet::remove_validator] — Force-remove from the approved set.
//!
//! ## Security
//!
//! - Only `AddRemoveOrigin` can grow the active set.
//! - `add_validator` requires the account to have session keys already registered:
//!   an approved account without keys would occupy a slot without authoring blocks.
//! - Leaving the set (by either path) notifies [`Config::OnValidatorRemoved`] so
//!   dependent state, such as the EVM relay binding, is cleaned up.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

pub mod weights;
pub use weights::WeightInfo;

pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub mod traits;
pub use traits::{OnValidatorRemoved, ValidatorPrerequisites, ValidatorSetInterface};

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::{pallet_prelude::*, traits::EnsureOrigin};
	use frame_system::pallet_prelude::*;
	use pallet_session::SessionManager;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	// ── Config ─────────────────────────────────────────────────────────────
	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Origin allowed to add and remove validators. Use `EnsureRoot` for sudo.
		type AddRemoveOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Maximum number of validators in the **approved** (active) set.
		#[pallet::constant]
		type MaxValidators: Get<u32>;

		/// Prerequisite gate checked on every `add_validator` call.
		///
		/// The account must already have session keys registered, otherwise it
		/// would hold a slot in the active set without being able to author.
		type Prerequisites: crate::ValidatorPrerequisites<Self::AccountId>;

		/// Notified whenever an account leaves the approved set.
		type OnValidatorRemoved: crate::OnValidatorRemoved<Self::AccountId>;

		/// Weight information for the pallet's dispatchables.
		type WeightInfo: crate::WeightInfo;
	}

	// ── Storage ────────────────────────────────────────────────────────────
	/// The approved (active) set of validator account IDs.
	///
	/// Included as block producers at every session rotation.
	/// Updated by `add_validator` and `remove_validator` (sudo), and by
	/// `deregister_validator` (the validator itself).
	#[pallet::storage]
	#[pallet::getter(fn approved_validators)]
	pub type ApprovedValidators<T: Config> =
		StorageValue<_, BoundedVec<T::AccountId, T::MaxValidators>, ValueQuery>;

	// ── Events ─────────────────────────────────────────────────────────────
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A validator was added by sudo. Takes effect next session.
		ValidatorAdded { validator: T::AccountId },
		/// A validator left the approved set, by sudo or voluntarily.
		ValidatorRemoved { validator: T::AccountId },
	}

	// ── Errors ─────────────────────────────────────────────────────────────
	#[pallet::error]
	pub enum Error<T> {
		/// The account is already in the approved validator set.
		AlreadyValidator,
		/// The account is not in the approved validator set.
		NotValidator,
		/// The approved set is full (`MaxValidators` reached).
		TooManyValidators,
		/// Session keys (Aura + GRANDPA) not yet registered via `session.setKeys`.
		NoSessionKeys,
	}

	// ── Genesis ────────────────────────────────────────────────────────────
	/// Genesis configuration: the list of initially approved validator accounts.
	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: Vec<T::AccountId>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		/// Note the session-key gate that `add_validator` enforces is deliberately
		/// **not** applied here: this pallet's genesis runs before
		/// `pallet_session`'s, so `NextKeys` is still empty and the check would
		/// reject every account. Chain-spec authors are responsible for seeding
		/// both from the same list.
		fn build(&self) {
			let bounded: BoundedVec<T::AccountId, T::MaxValidators> = self
				.initial_validators
				.clone()
				.try_into()
				.expect("Initial validators must not exceed MaxValidators");
			<ApprovedValidators<T>>::put(bounded);
		}
	}

	// ── Extrinsics ─────────────────────────────────────────────────────────
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		// Call indices 2, 4 and 5 belonged to the removed self-registration flow
		// (`register_validator`, `approve_validator`, `reject_validator`).
		// They are retired and must never be reassigned.

		// ── Sudo paths ─────────────────────────────────────────────────────────

		/// Add an operator to the approved set.
		///
		/// Requires `AddRemoveOrigin`. The account must already have session keys
		/// registered, otherwise it would hold a slot without authoring blocks.
		/// Takes effect at the next session rotation.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::add_validator())]
		pub fn add_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
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

		/// Force-remove an account from the approved set.
		///
		/// Requires `AddRemoveOrigin`. Takes effect at the next session rotation.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::remove_validator())]
		pub fn remove_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
			Self::remove_from_approved(&validator)?;
			Ok(())
		}

		// ── Self-service paths ─────────────────────────────────────────────────

		/// Leave the approved set voluntarily.
		///
		/// Takes effect at the next session rotation.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::remove_validator())]
		pub fn deregister_validator(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::remove_from_approved(&who)?;
			Ok(())
		}
	}

	// ── Internal helpers ───────────────────────────────────────────────────
	impl<T: Config> Pallet<T> {
		/// Drop `validator` from the approved set, notify the removal hook and
		/// emit `ValidatorRemoved`. Fails if the account is not in the set.
		fn remove_from_approved(validator: &T::AccountId) -> DispatchResult {
			ApprovedValidators::<T>::try_mutate(|validators| -> DispatchResult {
				let pos = validators
					.iter()
					.position(|v| v == validator)
					.ok_or(Error::<T>::NotValidator)?;
				validators.remove(pos);
				Ok(())
			})?;

			T::OnValidatorRemoved::on_validator_removed(validator);
			Self::deposit_event(Event::ValidatorRemoved {
				validator: validator.clone(),
			});
			Ok(())
		}
	}

	// ── ValidatorSetInterface implementation ───────────────────────────────
	impl<T: Config> crate::ValidatorSetInterface<T::AccountId> for Pallet<T> {
		fn is_active_validator(who: &T::AccountId) -> bool {
			ApprovedValidators::<T>::get().contains(who)
		}

		#[cfg(feature = "runtime-benchmarks")]
		fn setup_validator(who: &T::AccountId) {
			ApprovedValidators::<T>::try_mutate(|validators| -> Result<(), ()> {
				if !validators.contains(who) {
					validators.try_push(who.clone()).map_err(|_| ())?;
				}
				Ok(())
			})
			.expect("benchmark setup: ApprovedValidators is full; raise MaxValidators");
		}
	}

	// ── SessionManager implementation ──────────────────────────────────────
	/// `pallet_session::SessionManager` implementation.
	///
	/// Returns the current approved validator list on every new session, so
	/// add/remove changes take effect at session boundaries.
	impl<T: Config> SessionManager<T::AccountId> for Pallet<T> {
		/// Approved accounts that can still author are handed to `pallet_session`.
		///
		/// The session-key check is repeated here rather than trusted from
		/// `add_validator`: `session.purge_keys` is permissionless, so an approved
		/// validator can drop its keys at any time and would otherwise keep a slot
		/// in the schedule while producing nothing.
		fn new_session(_new_index: u32) -> Option<Vec<T::AccountId>> {
			Some(
				ApprovedValidators::<T>::get()
					.into_iter()
					.filter(T::Prerequisites::has_session_keys)
					.collect(),
			)
		}

		fn new_session_genesis(new_index: u32) -> Option<Vec<T::AccountId>> {
			Self::new_session(new_index)
		}

		fn start_session(_start_index: u32) {}

		fn end_session(_end_index: u32) {}
	}
}
