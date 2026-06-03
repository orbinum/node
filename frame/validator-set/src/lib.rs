//! # Pallet Validator Set
//!
//! Two-phase validator registration for Orbinum: self-registration with a bond deposit,
//! followed by explicit governance approval before the node joins the active set.
//!
//! ## Registration Flow
//!
//! 1. The candidate account holds **> 1 001 ORB** (1 000 bond + fees buffer).
//! 2. The candidate calls [`register_validator`][Pallet::register_validator], which locks
//!    `T::ValidatorBond` (1 000 ORB) and places the account in the **pending** queue.
//! 3. `AddRemoveOrigin` (sudo / governance) reviews and calls
//!    [`approve_validator`][Pallet::approve_validator] → account moves to the **approved** set
//!    and becomes an active block-producer at the next session rotation.
//! 4. To leave voluntarily, the validator calls [`deregister_validator`][Pallet::deregister_validator];
//!    the bond is returned immediately (whether still pending or already approved).
//!
//! ## Sudo Paths
//!
//! - [`add_validator`][Pallet::add_validator] — Directly add a trusted node (no bond).
//! - [`remove_validator`][Pallet::remove_validator] — Force-remove from pending or approved; bond returned.
//! - [`approve_validator`][Pallet::approve_validator] — Approve a pending registration.
//! - [`reject_validator`][Pallet::reject_validator] — Reject a pending registration; bond returned.
//!
//! ## Security
//!
//! - A non-approved account **never** enters the active validator set.
//! - The bond incentivises legitimate registrations and deters spam.
//! - Bond is always returned (approve → stay in set; reject/remove → immediate release;
//!   deregister → immediate release).

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
	use frame_support::{
		pallet_prelude::*,
		traits::{Currency, EnsureOrigin, ReservableCurrency},
	};
	use frame_system::pallet_prelude::*;
	use pallet_session::SessionManager;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Origin allowed to add/remove/approve/reject validators. Use `EnsureRoot` for sudo.
		type AddRemoveOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Currency used to reserve the validator bond on self-registration.
		type Currency: ReservableCurrency<Self::AccountId>;

		/// Maximum number of validators in the **approved** (active) set.
		#[pallet::constant]
		type MaxValidators: Get<u32>;

		/// Maximum number of registrations awaiting governance approval.
		#[pallet::constant]
		type MaxPendingValidators: Get<u32>;

		/// Bond (in native tokens) locked when a candidate calls `register_validator`.
		/// With 18 decimals: `1_000 * 10^18` = 1 000 ORB.
		#[pallet::constant]
		type ValidatorBond: Get<BalanceOf<Self>>;

		/// Prerequisite gate checked on every `register_validator` call.
		///
		/// The caller must have both session keys and an EVM relayer registered
		/// before they are allowed to lock the bond and enter the pending queue.
		type Prerequisites: crate::ValidatorPrerequisites<Self::AccountId>;

		/// Weight information for the pallet's dispatchables.
		type WeightInfo: crate::WeightInfo;
	}

	/// Shorthand for the currency balance type.
	pub type BalanceOf<T> =
		<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

	/// The approved (active) set of validator account IDs.
	///
	/// Included as block producers at every session rotation.
	/// Updated by `add_validator` (sudo) and `approve_validator` (sudo after bond).
	#[pallet::storage]
	#[pallet::getter(fn approved_validators)]
	pub type ApprovedValidators<T: Config> =
		StorageValue<_, BoundedVec<T::AccountId, T::MaxValidators>, ValueQuery>;

	/// Accounts that have self-registered (bond locked) and are awaiting governance approval.
	///
	/// Entries here are **not** included in the active session — they only become validators
	/// after `AddRemoveOrigin` calls `approve_validator`.
	#[pallet::storage]
	#[pallet::getter(fn pending_validators)]
	pub type PendingValidators<T: Config> =
		StorageValue<_, BoundedVec<T::AccountId, T::MaxPendingValidators>, ValueQuery>;

	/// Bond amount reserved at the time of self-registration (`register_validator`).
	/// Stored per-account so the exact amount is returned even if `T::ValidatorBond` changes.
	/// Validators added via sudo `add_validator` have no entry here.
	#[pallet::storage]
	pub type ValidatorBondOf<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, BalanceOf<T>, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A validator was directly added by sudo. Takes effect next session.
		ValidatorAdded { validator: T::AccountId },
		/// A validator was removed (approved or pending). Bond returned if held.
		ValidatorRemoved { validator: T::AccountId },
		/// A self-registration was submitted; awaiting governance approval.
		ValidatorRegistrationRequested { validator: T::AccountId },
		/// A pending registration was approved. Takes effect next session.
		ValidatorApproved { validator: T::AccountId },
		/// A pending registration was rejected; bond returned.
		ValidatorRejected { validator: T::AccountId },
		/// Bond reserved when a candidate self-registered.
		ValidatorBondReserved {
			validator: T::AccountId,
			amount: BalanceOf<T>,
		},
		/// Bond released on deregistration, removal, or rejection.
		ValidatorBondReleased {
			validator: T::AccountId,
			amount: BalanceOf<T>,
		},
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
		/// Account does not have enough free balance to cover `ValidatorBond`.
		InsufficientBond,
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

		/// Directly add a trusted account to the approved set (no bond required).
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
		/// Requires `AddRemoveOrigin`. If the account had a bond, it is returned.
		/// Takes effect at the next session rotation (for approved validators).
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
			Self::release_bond(&validator);
			Self::deposit_event(Event::ValidatorRemoved { validator });
			Ok(())
		}

		/// Approve a pending validator registration.
		///
		/// Requires `AddRemoveOrigin`. Moves the account from the pending queue to the
		/// approved set. The bond remains locked. Takes effect at the next session rotation.
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

		/// Reject a pending validator registration and return the bond.
		///
		/// Requires `AddRemoveOrigin`. The applicant is removed from the pending queue
		/// and their `ValidatorBond` is unreserved in full.
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

			Self::release_bond(&validator);
			Self::deposit_event(Event::ValidatorRejected { validator });
			Ok(())
		}

		// ── Self-service paths ────────────────────────────────────────────────────

		/// Submit a validator registration request by locking `T::ValidatorBond` tokens.
		///
		/// The caller is placed in the **pending** queue — they do NOT become an active
		/// validator until `AddRemoveOrigin` calls `approve_validator`. The bond is held
		/// until the account is approved, rejected, or calls `deregister_validator`.
		///
		/// The caller must have **> `ValidatorBond`** free balance to also cover
		/// any subsequent transaction fees (e.g., registering the EVM relay address).
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::add_validator())]
		pub fn register_validator(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let bond = T::ValidatorBond::get();

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
				T::Currency::reserve(&who, bond).map_err(|_| Error::<T>::InsufficientBond)?;
				ValidatorBondOf::<T>::insert(&who, bond);
				pending
					.try_push(who.clone())
					.map_err(|_| Error::<T>::TooManyPending)
			})?;

			Self::deposit_event(Event::ValidatorBondReserved {
				validator: who.clone(),
				amount: bond,
			});
			Self::deposit_event(Event::ValidatorRegistrationRequested { validator: who });
			Ok(())
		}

		/// Cancel a pending registration or self-remove from the approved set.
		///
		/// Works from both the **pending** queue and the **approved** set. The bond
		/// (if held) is returned immediately. Removal from the approved set takes effect
		/// at the next session rotation.
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

			Self::release_bond(&who);
			Self::deposit_event(Event::ValidatorRemoved { validator: who });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Unreserve the bond held for `who` (if any) and emit `ValidatorBondReleased`.
		fn release_bond(who: &T::AccountId) {
			if let Some(bond) = ValidatorBondOf::<T>::take(who) {
				T::Currency::unreserve(who, bond);
				Self::deposit_event(Event::ValidatorBondReleased {
					validator: who.clone(),
					amount: bond,
				});
			}
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
