//! # Pallet Validator Set
//!
//! Two-phase validator registration for Orbinum: permissionless self-registration,
//! followed by explicit governance approval before the node joins the active set.
//!
//! ## Registration Flow
//!
//! 1. The candidate registers session keys (`session.setKeys`) and an EVM relay address
//!    (`relayer.register_relayer`).
//! 2. The candidate calls [`register_validator`][Pallet::register_validator], which places
//!    the account in the **pending** queue.
//! 3. `AddRemoveOrigin` (sudo / governance) reviews and calls
//!    [`approve_validator`][Pallet::approve_validator] → account moves to the **approved** set
//!    and becomes an active block-producer at the next session rotation.
//! 4. To leave voluntarily, the validator calls [`deregister_validator`][Pallet::deregister_validator].
//!
//! ## Sudo Paths
//!
//! - [`add_validator`][Pallet::add_validator] — Directly add a trusted node.
//! - [`remove_validator`][Pallet::remove_validator] — Force-remove from pending or approved.
//! - [`approve_validator`][Pallet::approve_validator] — Approve a pending registration.
//! - [`reject_validator`][Pallet::reject_validator] — Reject a pending registration.
//!
//! ## Security
//!
//! - A non-approved account **never** enters the active validator set.
//! - Registration takes no bond. Spam is bounded by `MaxPendingValidators` and by
//!   the session-key and relayer prerequisites. Note that `register_relayer` is
//!   itself `ManageOrigin`-gated, so in practice only accounts governance has
//!   already touched can enter the pending queue at all.

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

/// Prerequisite checks injected into [`pallet::Config`].
///
/// Implement this trait in the runtime using `pallet_session` and `pallet_relayer`
/// storage. Use a stub in tests.
pub trait ValidatorPrerequisites<AccountId> {
	/// Returns `true` if the account has registered both Aura and GRANDPA session keys
	/// via `pallet_session` (`session.setKeys`).
	fn has_session_keys(who: &AccountId) -> bool;

	/// Returns `true` if the account has a registered EVM relay address
	/// via `pallet_relayer` (`relayer.register_relayer`).
	fn has_relayer(who: &AccountId) -> bool;
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::{pallet_prelude::*, traits::EnsureOrigin};
	use frame_system::pallet_prelude::*;
	use pallet_session::SessionManager;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Origin allowed to add/remove/approve/reject validators. Use `EnsureRoot` for sudo.
		type AddRemoveOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Maximum number of validators in the **approved** (active) set.
		#[pallet::constant]
		type MaxValidators: Get<u32>;

		/// Maximum number of registrations awaiting governance approval.
		#[pallet::constant]
		type MaxPendingValidators: Get<u32>;

		/// Prerequisite gate checked on every `register_validator` call.
		///
		/// The caller must have both session keys and an EVM relayer registered
		/// before they are allowed to enter the pending queue.
		type Prerequisites: crate::ValidatorPrerequisites<Self::AccountId>;

		/// Weight information for the pallet's dispatchables.
		type WeightInfo: crate::WeightInfo;
	}

	/// The approved (active) set of validator account IDs.
	///
	/// Included as block producers at every session rotation.
	/// Updated by `add_validator` (sudo) and `approve_validator` (sudo).
	#[pallet::storage]
	#[pallet::getter(fn approved_validators)]
	pub type ApprovedValidators<T: Config> =
		StorageValue<_, BoundedVec<T::AccountId, T::MaxValidators>, ValueQuery>;

	/// Accounts that have self-registered and are awaiting governance approval.
	///
	/// Entries here are **not** included in the active session — they only become validators
	/// after `AddRemoveOrigin` calls `approve_validator`.
	#[pallet::storage]
	#[pallet::getter(fn pending_validators)]
	pub type PendingValidators<T: Config> =
		StorageValue<_, BoundedVec<T::AccountId, T::MaxPendingValidators>, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A validator was directly added by sudo. Takes effect next session.
		ValidatorAdded { validator: T::AccountId },
		/// A validator was removed (approved or pending).
		ValidatorRemoved { validator: T::AccountId },
		/// A self-registration was submitted; awaiting governance approval.
		ValidatorRegistrationRequested { validator: T::AccountId },
		/// A pending registration was approved. Takes effect next session.
		ValidatorApproved { validator: T::AccountId },
		/// A pending registration was rejected.
		ValidatorRejected { validator: T::AccountId },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The account is already in the approved validator set.
		AlreadyValidator,
		/// The account is already in the pending registration queue.
		AlreadyPending,
		/// The account is not in the approved validator set.
		NotValidator,
		/// The account is not in the pending registration queue.
		NotPending,
		/// The approved set is full (`MaxValidators` reached).
		TooManyValidators,
		/// The pending queue is full (`MaxPendingValidators` reached).
		TooManyPending,
		/// Session keys (Aura + GRANDPA) not yet registered via `session.setKeys`.
		NoSessionKeys,
		/// EVM relay address not yet registered via `relayer.register_relayer`.
		NoRelayer,
	}

	/// Genesis configuration: the list of initially approved validator accounts.
	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: Vec<T::AccountId>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			let bounded: BoundedVec<T::AccountId, T::MaxValidators> = self
				.initial_validators
				.clone()
				.try_into()
				.expect("Initial validators must not exceed MaxValidators");
			<ApprovedValidators<T>>::put(bounded);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		// ── Sudo paths ───────────────────────────────────────────────────────────────────

		/// Directly add a trusted account to the approved set.
		///
		/// Requires `AddRemoveOrigin`. The account must not be in the pending queue.
		/// Takes effect at the next session rotation.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::add_validator())]
		pub fn add_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
			// A pending account must be explicitly approved, not bypassed via sudo add.
			ensure!(
				!PendingValidators::<T>::get().contains(&validator),
				Error::<T>::AlreadyPending
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

		/// Force-remove an account from the approved set or the pending queue.
		///
		/// Requires `AddRemoveOrigin`. Takes effect at the next session rotation
		/// (for approved validators).
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::remove_validator())]
		pub fn remove_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			// Remove from approved set.
			let in_approved = ApprovedValidators::<T>::mutate(|validators| {
				if let Some(pos) = validators.iter().position(|v| v == &validator) {
					validators.remove(pos);
					true
				} else {
					false
				}
			});

			// If not approved, try the pending queue.
			let in_pending = if !in_approved {
				PendingValidators::<T>::mutate(|pending| {
					if let Some(pos) = pending.iter().position(|v| v == &validator) {
						pending.remove(pos);
						true
					} else {
						false
					}
				})
			} else {
				false
			};

			ensure!(in_approved || in_pending, Error::<T>::NotValidator);
			Self::deposit_event(Event::ValidatorRemoved { validator });
			Ok(())
		}

		/// Approve a pending validator registration.
		///
		/// Requires `AddRemoveOrigin`. Moves the account from the pending queue to the
		/// approved set. Takes effect at the next session rotation.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::add_validator())]
		pub fn approve_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			// Remove from pending — fails if not pending.
			PendingValidators::<T>::try_mutate(|pending| -> DispatchResult {
				let pos = pending
					.iter()
					.position(|v| v == &validator)
					.ok_or(Error::<T>::NotPending)?;
				pending.remove(pos);
				Ok(())
			})?;

			// Add to approved — defensive: should never already be there.
			ApprovedValidators::<T>::try_mutate(|validators| {
				ensure!(
					!validators.contains(&validator),
					Error::<T>::AlreadyValidator
				);
				validators
					.try_push(validator.clone())
					.map_err(|_| Error::<T>::TooManyValidators)
			})?;

			Self::deposit_event(Event::ValidatorApproved { validator });
			Ok(())
		}

		/// Reject a pending validator registration.
		///
		/// Requires `AddRemoveOrigin`. The applicant is removed from the pending queue.
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::remove_validator())]
		pub fn reject_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			PendingValidators::<T>::try_mutate(|pending| -> DispatchResult {
				let pos = pending
					.iter()
					.position(|v| v == &validator)
					.ok_or(Error::<T>::NotPending)?;
				pending.remove(pos);
				Ok(())
			})?;

			Self::deposit_event(Event::ValidatorRejected { validator });
			Ok(())
		}

		// ── Self-service paths ────────────────────────────────────────────────────

		/// Submit a validator registration request.
		///
		/// The caller is placed in the **pending** queue — they do NOT become an active
		/// validator until `AddRemoveOrigin` calls `approve_validator`.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::add_validator())]
		pub fn register_validator(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Reject if already active or already pending.
			ensure!(
				!ApprovedValidators::<T>::get().contains(&who),
				Error::<T>::AlreadyValidator
			);

			// Enforce prerequisite checks: session keys and EVM relayer must be registered.
			ensure!(
				T::Prerequisites::has_session_keys(&who),
				Error::<T>::NoSessionKeys
			);
			ensure!(T::Prerequisites::has_relayer(&who), Error::<T>::NoRelayer);

			PendingValidators::<T>::try_mutate(|pending| {
				ensure!(!pending.contains(&who), Error::<T>::AlreadyPending);
				pending
					.try_push(who.clone())
					.map_err(|_| Error::<T>::TooManyPending)
			})?;

			Self::deposit_event(Event::ValidatorRegistrationRequested { validator: who });
			Ok(())
		}

		/// Cancel a pending registration or self-remove from the approved set.
		///
		/// Works from both the **pending** queue and the **approved** set. Removal from
		/// the approved set takes effect at the next session rotation.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::remove_validator())]
		pub fn deregister_validator(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Try pending first.
			let removed_from_pending = PendingValidators::<T>::mutate(|pending| {
				if let Some(pos) = pending.iter().position(|v| v == &who) {
					pending.remove(pos);
					true
				} else {
					false
				}
			});

			if !removed_from_pending {
				// Try approved set.
				ApprovedValidators::<T>::try_mutate(|validators| -> DispatchResult {
					let pos = validators
						.iter()
						.position(|v| v == &who)
						.ok_or(Error::<T>::NotValidator)?;
					validators.remove(pos);
					Ok(())
				})?;
			}

			Self::deposit_event(Event::ValidatorRemoved { validator: who });
			Ok(())
		}
	}

	/// `pallet_session::SessionManager` implementation.
	///
	/// Returns the current approved validator list on every new session, applying
	/// any pending add/remove changes at session boundaries.
	impl<T: Config> SessionManager<T::AccountId> for Pallet<T> {
		fn new_session(_new_index: u32) -> Option<Vec<T::AccountId>> {
			Some(ApprovedValidators::<T>::get().into_inner())
		}

		fn new_session_genesis(new_index: u32) -> Option<Vec<T::AccountId>> {
			Self::new_session(new_index)
		}

		fn start_session(_start_index: u32) {}

		fn end_session(_end_index: u32) {}
	}
}
