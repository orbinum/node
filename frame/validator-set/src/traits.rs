//! Public traits exposed by pallet-validator-set.
//!
//! Mirrors the port pattern used by `pallet_relayer::RelayerInterface`: other
//! pallets depend on these traits, never on concrete storage. Tests supply
//! lightweight mock implementations in their own `mock.rs`.

/// Read access to the approved validator set.
///
/// Production impl: `pallet_validator_set::Pallet<T>`.
/// Consumed by `pallet-relayer` to gate EVM relay address registration on
/// membership of the active set.
pub trait ValidatorSetInterface<AccountId> {
	/// Returns `true` when `who` is in the approved (active) validator set.
	fn is_active_validator(who: &AccountId) -> bool;

	/// Put `who` in the approved set so a dependent pallet's benchmarks can pass
	/// a membership gate.
	///
	/// Implementors must repeat this `cfg` attribute verbatim, or the trait will
	/// fail to compile only when the `runtime-benchmarks` feature is enabled.
	#[cfg(feature = "runtime-benchmarks")]
	fn setup_validator(who: &AccountId);
}

/// Denies everything.
///
/// Deliberate: a permissive default would silently disable any gate built on
/// this trait in a runtime that forgot to wire a real implementation.
impl<AccountId> ValidatorSetInterface<AccountId> for () {
	fn is_active_validator(_who: &AccountId) -> bool {
		false
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_validator(_who: &AccountId) {}
}

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
	/// Implementors must repeat this `cfg` attribute verbatim — see
	/// [`ValidatorSetInterface::setup_validator`].
	#[cfg(feature = "runtime-benchmarks")]
	fn setup_session_keys(who: &AccountId);
}

/// Notified when an account leaves the approved validator set.
///
/// Lets the runtime clean up state that is only valid while the account is an
/// active validator — for instance the EVM relay binding in `pallet-relayer`.
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
	/// [`ValidatorSetInterface::setup_validator`].
	#[cfg(feature = "runtime-benchmarks")]
	fn setup_removal_state(who: &AccountId);
}

/// Tuple impl, so a runtime can subscribe several consumers:
/// `type OnValidatorRemoved = (RelayerCleanup, SomethingElse);`
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
