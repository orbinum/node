//! What the runtime plugs into the pallet: the session-key check, the open-mode
//! safeguard, the removal hook, the candidacy check and the benchmarks' setup. Tests supply
//! lightweight mocks in `tests/mock.rs`.
//!
//! Whether an account may validate is not a trait here: read
//! [`Pallet::admission`](crate::Pallet::admission), the one answer that covers
//! the mode, the allowlist, bans and session keys.

/// Prerequisite checks injected into [`crate::pallet::Config`].
///
/// Implement this in the runtime using `pallet_session` storage; use a stub in
/// tests.
pub trait ValidatorPrerequisites<AccountId> {
	/// Returns `true` if the account has registered both Aura and GRANDPA session
	/// keys via `pallet_session` (`session.setKeys`).
	fn has_session_keys(who: &AccountId) -> bool;

	/// Register session keys for `who` so `add_validator` benchmarks pass the gate.
	///
	/// Implementors must repeat this `cfg` attribute verbatim, or the trait will
	/// fail to compile only when the `runtime-benchmarks` feature is enabled.
	#[cfg(feature = "runtime-benchmarks")]
	fn setup_session_keys(who: &AccountId);
}

/// Whether the validator set may switch to [`AdmissionMode::Open`](crate::AdmissionMode).
///
/// The runtime ties it to safeguards this pallet does not know about, such as a
/// minimum self-bond high enough to make sybil candidates expensive.
pub trait OpenModeGuard {
	fn can_open() -> bool;

	/// Put the runtime's safeguards in place so `set_admission_mode` benchmarks
	/// can open.
	///
	/// Implementors must repeat this `cfg` attribute verbatim — see
	/// [`ValidatorPrerequisites::setup_session_keys`].
	#[cfg(feature = "runtime-benchmarks")]
	fn setup_can_open();
}

/// Never opens: a runtime that wired no safeguard keeps the set permissioned.
impl OpenModeGuard for () {
	fn can_open() -> bool {
		false
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_can_open() {}
}

/// Notified when an account loses the right to validate: it leaves the approved
/// set or is banned.
///
/// Lets the runtime stop the account validating and clean up state that is only
/// valid while it may (e.g. chill its staking candidacy).
///
/// Deliberately infallible: leaving the set must always succeed, so a failure to
/// clean up dependent state can never block removal. A no-op is the safe default
/// because dependent cleanup is opt-in — a runtime with nothing to clean up
/// should not have to write anything.
pub trait OnValidatorRemoved<AccountId> {
	fn on_validator_removed(who: &AccountId);

	/// Create whatever state this hook would have to clean up, so
	/// `remove_validator` benchmarks measure the expensive branch.
	///
	/// Without it the benchmark removes an account with nothing attached, the
	/// hook short-circuits, and the recorded weight misses the cleanup writes.
	///
	/// Implementors must repeat this `cfg` attribute verbatim — see
	/// [`ValidatorPrerequisites::setup_session_keys`].
	#[cfg(feature = "runtime-benchmarks")]
	fn setup_removal_state(who: &AccountId);
}

/// Tuple impl, so a runtime can subscribe several consumers:
/// `type OnValidatorRemoved = (FirstCleanup, SecondCleanup);`
///
/// This also covers `()` — the empty tuple is the no-op default, which is safe
/// because dependent cleanup is opt-in.
#[impl_trait_for_tuples::impl_for_tuples(8)]
impl<AccountId> OnValidatorRemoved<AccountId> for Tuple {
	fn on_validator_removed(who: &AccountId) {
		for_tuples!( #( Tuple::on_validator_removed(who); )* );
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_removal_state(who: &AccountId) {
		for_tuples!( #( Tuple::setup_removal_state(who); )* );
	}
}

/// Whether a staking candidate has lost its admission, as the runtime judges
/// it. [`Pallet::chill_inadmissible`](crate::Pallet::chill_inadmissible) lets
/// anyone end such a candidacy, which otherwise holds a candidate slot that
/// only governance could free.
pub trait Candidacy<AccountId> {
	/// `who` offers itself as a validator and the runtime would no longer admit
	/// it.
	fn is_inadmissible_candidate(who: &AccountId) -> bool;
}

/// No candidates: a runtime without staking has nothing to chill.
impl<AccountId> Candidacy<AccountId> for () {
	fn is_inadmissible_candidate(_: &AccountId) -> bool {
		false
	}
}

/// Benchmark setup the pallet cannot do through its own storage.
#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper<AccountId> {
	/// Make `validators` what [`crate::Config::ActiveValidators`] and
	/// [`crate::Config::QueuedValidators`] return, so `set_min_author_version`
	/// measures a full quorum.
	fn set_active_validators(validators: alloc::vec::Vec<AccountId>);
}
