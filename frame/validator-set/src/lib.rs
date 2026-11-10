//! # Pallet Validator Set
//!
//! Decides who may be a validator candidate for Orbinum. It does not pick the
//! active set: the runtime's election does, among the candidates this pallet
//! admits ([`admission`]).
//!
//! ## Admission
//!
//! An account may validate when it is not banned, has session keys and, while the
//! [`AdmissionMode`] is `Permissioned`, is in [`ApprovedValidators`]. In `Open`
//! mode the allowlist is ignored; switching to it is refused unless
//! [`Config::OpenModeGuard`] allows it, so the runtime can demand its economic
//! safeguards first.
//!
//! ## Onboarding Flow (permissioned)
//!
//! 1. The operator registers session keys on their own node (`session.setKeys`).
//!    The private key never leaves their machine, so this step cannot be done for them.
//! 2. `AddRemoveOrigin` (sudo / governance) calls
//!    [`add_validator`][Pallet::add_validator] with the operator's `AccountId`.
//!
//! ## Leaving
//!
//! Either [`remove_validator`][Pallet::remove_validator] (sudo) or
//! [`deregister_validator`][Pallet::deregister_validator] (the validator itself).
//! Both notify [`Config::OnValidatorRemoved`].
//!
//! ## Bans
//!
//! A banned account is not admitted in either mode until the ban ends.
//! [`ban_validator`][Pallet::ban_validator] sets one (temporary or permanent),
//! [`unban_validator`][Pallet::unban_validator] lifts it, and the runtime bans
//! offenders through [`Pallet::ban_offender`], which never shortens a ban in
//! force. A ban also notifies [`Config::OnValidatorRemoved`], so the account
//! stops validating at once rather than at its ban's next check.
//!
//! ## Security
//!
//! - Only `AddRemoveOrigin` can admit accounts, ban them or change the mode.
//! - `add_validator` requires session keys already registered and refuses banned
//!   accounts; the allowlist never holds an account twice, genesis included.
//! - Losing the right to validate (removal or ban) notifies
//!   [`Config::OnValidatorRemoved`] so dependent state can be cleaned up, and
//!   drops the account's declared version so it no longer counts toward a
//!   version quorum.
//! - Whether an account may validate has one answer, [`Pallet::admission`]:
//!   the allowlist alone is not it (it does not hold in `Open` mode, nor for a
//!   banned account or one without session keys).
//!
//! ## Minimum author version
//!
//! Each block's author declares its node version in an inherent
//! ([`author_version`]). [`set_min_author_version`][Pallet::set_min_author_version]
//! makes a block invalid unless its author declared at least that version, so a
//! lagging binary loses its slots until it upgrades. It is refused unless 2/3 of
//! the set, and of the set queued for the next session, already authored with
//! that version within [`Config::QuorumWindow`], so neither is left without
//! authors. Validators elected later are not checked: an operator upgrades
//! before validating. With no minimum set, any binary may author.
//!
//! ## Layout
//!
//! - [`types`]: the admission vocabulary, the declared [`NodeVersion`] and
//!   [`traits`], what the runtime plugs in.
//! - `engine`: the pallet's logic, one module per concern: [`admission`]
//!   (reading the rules, the [`admission::allowlist`] and [`admission::bans`]),
//!   [`author_version`] (the version each author declares and its minimum) and
//!   the invariants.
//! - `benchmarking`: the benchmarks and the [`weights`] they produce.
//! - `tests`: the mock runtime and the tests, grouped by concern as `engine` is.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

pub mod types;

mod benchmarking;
mod engine;

#[cfg(test)]
mod tests;

pub use benchmarking::weights;
pub use engine::{admission, author_version};
pub use types::traits;

pub use admission::Admission;
pub use pallet::*;
pub use traits::{Candidacy, OnValidatorRemoved, OpenModeGuard, ValidatorPrerequisites};
pub use types::{AdmissionMode, BanTerm, Inadmissible, NodeVersion};
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use crate::author_version::INHERENT_IDENTIFIER;
	use frame_support::{
		pallet_prelude::*,
		traits::{EnsureOrigin, FindAuthor},
	};
	use frame_system::pallet_prelude::*;

	/// 1: adds the admission mode and bans.
	const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	// ── Config ─────────────────────────────────────────────────────────────
	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Origin allowed to add and remove validators. Use `EnsureRoot` for sudo.
		type AddRemoveOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Maximum number of accounts in the allowlist ([`ApprovedValidators`]).
		#[pallet::constant]
		type MaxValidators: Get<u32>;

		/// Prerequisite gate checked on every `add_validator` call.
		///
		/// The account must already have session keys registered, otherwise it
		/// would hold a slot in the active set without being able to author.
		type Prerequisites: crate::ValidatorPrerequisites<Self::AccountId>;

		/// Notified whenever an account loses the right to validate: removed from
		/// the approved set or banned.
		type OnValidatorRemoved: crate::OnValidatorRemoved<Self::AccountId>;

		/// Whether the set may switch to [`AdmissionMode::Open`] now. The runtime
		/// ties it to its economic safeguards (e.g. a minimum self-bond), which
		/// this pallet does not know about.
		type OpenModeGuard: crate::OpenModeGuard;

		/// Whether a staking candidate has lost its admission; such a candidacy
		/// is ended through [`Config::OnValidatorRemoved`] by
		/// [`Pallet::chill_inadmissible`].
		type Candidacy: crate::Candidacy<Self::AccountId>;

		/// The validators of the current session, whose declared versions make the
		/// quorum [`Pallet::set_min_author_version`] requires. Not the allowlist:
		/// an approved account that was not elected cannot author, so it cannot
		/// declare.
		type ActiveValidators: Get<Vec<Self::AccountId>>;

		/// The validators queued for the next session. A new minimum needs their
		/// quorum too, so a set about to rotate in cannot be left without
		/// authors.
		type QueuedValidators: Get<Vec<Self::AccountId>>;

		/// Which [`Config::ActiveValidators`] are disabled this session, by index
		/// into that list (the runtime's `Session`). They cannot author, so they
		/// never count toward the quorum.
		type DisabledValidators: frame_support::traits::DisabledValidators;

		/// The validator account that authored the current block, from its
		/// pre-runtime digests: an account in [`Config::ActiveValidators`], not
		/// the author's consensus key. A declaration from an author it cannot
		/// place there is dropped, and that validator never counts toward a quorum.
		type FindAuthor: FindAuthor<Self::AccountId>;

		/// How recent a validator's declared version must be to count toward the
		/// quorum [`Pallet::set_min_author_version`] requires. One session is enough
		/// for every active validator to author at least once.
		#[pallet::constant]
		type QuorumWindow: Get<BlockNumberFor<Self>>;

		/// Sets up what the benchmarks need outside this pallet.
		#[cfg(feature = "runtime-benchmarks")]
		type BenchmarkHelper: crate::traits::BenchmarkHelper<Self::AccountId>;

		/// Weight information for the pallet's dispatchables.
		type WeightInfo: crate::WeightInfo;
	}

	// ── Storage ────────────────────────────────────────────────────────────
	/// The allowlist: accounts admitted while the mode is `Permissioned`.
	///
	/// Updated by `add_validator` and `remove_validator` (sudo), and by
	/// `deregister_validator` (the validator itself).
	#[pallet::storage]
	pub type ApprovedValidators<T: Config> =
		StorageValue<_, BoundedVec<T::AccountId, T::MaxValidators>, ValueQuery>;

	/// The oldest node version a block author may run. `None`: any version, or none
	/// declared at all.
	#[pallet::storage]
	pub type MinAuthorVersion<T: Config> = StorageValue<_, NodeVersion, OptionQuery>;

	/// The node version each validator last declared, and the block it did so in.
	#[pallet::storage]
	pub type LastAuthorVersion<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		(NodeVersion, BlockNumberFor<T>),
		OptionQuery,
	>;

	/// Whether the current block's author declared a version. Cleared every block.
	#[pallet::storage]
	pub type AuthorVersionNoted<T: Config> = StorageValue<_, bool, ValueQuery>;

	/// The current block's author, if it is an active validator, resolved
	/// before the block's hooks can rotate the session. Cleared every block.
	#[pallet::storage]
	pub type BlockAuthor<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

	/// Whether the allowlist gates candidacy.
	#[pallet::storage]
	pub type Mode<T: Config> = StorageValue<_, AdmissionMode, ValueQuery>;

	/// Banned accounts and how long each ban lasts. An expired entry is inert and
	/// stays until it is overwritten or lifted: only governance and reported
	/// offences write here, which bounds it.
	#[pallet::storage]
	pub type Bans<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, BanTerm<BlockNumberFor<T>>, OptionQuery>;

	// ── Events ─────────────────────────────────────────────────────────────
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A validator was added by sudo. Takes effect next session.
		ValidatorAdded { validator: T::AccountId },
		/// A validator left the approved set, by sudo or voluntarily.
		ValidatorRemoved { validator: T::AccountId },
		/// The minimum author version changed; `None` lifts it.
		MinAuthorVersionSet { version: Option<NodeVersion> },
		/// The admission mode changed.
		AdmissionModeSet { mode: AdmissionMode },
		/// An account was banned from validating, by governance or for an offence.
		ValidatorBanned {
			validator: T::AccountId,
			term: BanTerm<BlockNumberFor<T>>,
		},
		/// A ban was lifted before it ended.
		ValidatorUnbanned { validator: T::AccountId },
		/// A candidacy the runtime no longer admits was ended.
		CandidacyEnded { validator: T::AccountId },
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
		/// Fewer than 2/3 of the active validators authored with that version
		/// within `QuorumWindow`, or there are none: setting it could leave the
		/// chain without authors.
		VersionQuorumNotMet,
		/// The author declared a version below `MinAuthorVersion`.
		AuthorVersionTooOld,
		/// The author's version was already declared in this block.
		AuthorVersionAlreadyNoted,
		/// The account is banned from validating.
		Banned,
		/// The account has no ban to lift.
		NotBanned,
		/// A temporary ban must end after the current block.
		BanAlreadyExpired,
		/// The runtime's safeguards for open admission are not in place.
		OpenModeGuardFailed,
		/// The account is not a candidate, or the runtime still admits it.
		CandidacyAdmissible,
	}

	// ── Hooks ──────────────────────────────────────────────────────────────
	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
			Self::note_block_author();
			// Here: the digest, the author lookup (Aura's authorities and the
			// session's validators) and the author. In `on_finalize`: the author,
			// the flag, the minimum and, for an undeclared block, the author's
			// entry.
			T::DbWeight::get().reads_writes(6, 4)
		}

		/// Rejects the block if a minimum is set and its author declared no
		/// version.
		fn on_finalize(_n: BlockNumberFor<T>) {
			Self::settle_author_declaration();
		}

		#[cfg(feature = "try-runtime")]
		fn try_state(_: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
			Self::do_try_state()
		}
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
		/// both from the same list. An account listed twice is refused: removing
		/// it would drop only one entry and leave it approved.
		fn build(&self) {
			let unique: alloc::collections::BTreeSet<_> = self.initial_validators.iter().collect();
			assert!(
				unique.len() == self.initial_validators.len(),
				"Initial validators must not list an account twice"
			);
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
		/// Requires `AddRemoveOrigin`. The account must not be banned and must
		/// already have session keys registered, otherwise it would hold a slot
		/// without authoring blocks.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::add_validator())]
		pub fn add_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
			Self::add_to_approved(validator)
		}

		/// Force-remove an account from the approved set.
		///
		/// Requires `AddRemoveOrigin`.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::remove_validator())]
		pub fn remove_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
			Self::remove_from_approved(&validator)
		}

		// ── Self-service paths ─────────────────────────────────────────────────

		/// Leave the approved set voluntarily.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::remove_validator())]
		pub fn deregister_validator(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::remove_from_approved(&who)
		}

		// ── Minimum author version ─────────────────────────────────────────────

		/// Set, or with `None` lift, the oldest node version a block author may run.
		///
		/// Requires `AddRemoveOrigin`. Setting a version is refused unless 2/3 of the
		/// active validators authored with at least that version within
		/// `QuorumWindow`; lifting it is always allowed.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::set_min_author_version())]
		pub fn set_min_author_version(
			origin: OriginFor<T>,
			version: Option<NodeVersion>,
		) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
			if let Some(min) = &version {
				ensure!(
					Self::has_version_quorum(min),
					Error::<T>::VersionQuorumNotMet
				);
			}
			MinAuthorVersion::<T>::set(version);
			Self::deposit_event(Event::MinAuthorVersionSet { version });
			Ok(())
		}

		/// The block author's declared node version. Inherent: one per block,
		/// provided by the author's node.
		#[pallet::call_index(7)]
		#[pallet::weight((T::WeightInfo::note_author_version(), DispatchClass::Mandatory))]
		pub fn note_author_version(origin: OriginFor<T>, version: NodeVersion) -> DispatchResult {
			ensure_none(origin)?;
			Self::note_declaration(version)
		}

		// ── Admission ──────────────────────────────────────────────────────────

		/// Set whether the allowlist gates candidacy.
		///
		/// Requires `AddRemoveOrigin`. Opening is refused unless
		/// [`Config::OpenModeGuard`] allows it; returning to `Permissioned` is
		/// always allowed.
		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::set_admission_mode())]
		pub fn set_admission_mode(origin: OriginFor<T>, mode: AdmissionMode) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
			if mode == AdmissionMode::Open {
				ensure!(
					T::OpenModeGuard::can_open(),
					Error::<T>::OpenModeGuardFailed
				);
			}
			Mode::<T>::put(mode);
			Self::deposit_event(Event::AdmissionModeSet { mode });
			Ok(())
		}

		/// Ban an account from validating, replacing any ban it already has.
		///
		/// Requires `AddRemoveOrigin`. The account stops validating at once
		/// ([`Config::OnValidatorRemoved`]) and is not admitted in either mode
		/// until the ban ends. It stays in the allowlist and keeps its stake.
		#[pallet::call_index(9)]
		#[pallet::weight(T::WeightInfo::ban_validator())]
		pub fn ban_validator(
			origin: OriginFor<T>,
			validator: T::AccountId,
			term: BanTerm<BlockNumberFor<T>>,
		) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
			ensure!(
				term.active_at(frame_system::Pallet::<T>::block_number()),
				Error::<T>::BanAlreadyExpired
			);
			Self::ban(&validator, term);
			Ok(())
		}

		/// Lift an account's ban, expired or not.
		///
		/// Requires `AddRemoveOrigin`. The account is admitted again on the usual
		/// terms; it has to offer itself as a validator again to be elected.
		#[pallet::call_index(10)]
		#[pallet::weight(T::WeightInfo::unban_validator())]
		pub fn unban_validator(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;
			Self::lift_ban(validator)
		}

		/// End the candidacy of an account the runtime no longer admits: no
		/// session keys, a self-bond below the minimum, a commission above the
		/// ceiling, or not approved while admission is permissioned.
		///
		/// Any signed account. The election already ignores such a candidate,
		/// but it keeps a candidate slot until this frees it. Fails with
		/// `CandidacyAdmissible` otherwise, and the caller pays the fee.
		#[pallet::call_index(11)]
		#[pallet::weight(T::WeightInfo::chill_inadmissible())]
		pub fn chill_inadmissible(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
			ensure_signed(origin)?;
			ensure!(
				T::Candidacy::is_inadmissible_candidate(&validator),
				Error::<T>::CandidacyAdmissible
			);
			T::OnValidatorRemoved::on_validator_removed(&validator);
			Self::deposit_event(Event::CandidacyEnded { validator });
			Ok(())
		}
	}

	// ── Inherent ───────────────────────────────────────────────────────────
	#[pallet::inherent]
	impl<T: Config> ProvideInherent for Pallet<T> {
		type Call = Call<T>;
		type Error = sp_inherents::MakeFatalError<()>;
		const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

		/// A node that provides no version (one predating this inherent) yields no
		/// call, and neither does one the chain would refuse; `on_finalize` decides
		/// whether that block may stand.
		fn create_inherent(data: &InherentData) -> Option<Self::Call> {
			let version = data
				.get_data::<NodeVersion>(&INHERENT_IDENTIFIER)
				.ok()
				.flatten()?;
			Self::declaration_call(version)
		}

		fn is_inherent(call: &Self::Call) -> bool {
			matches!(call, Call::note_author_version { .. })
		}
	}
}
