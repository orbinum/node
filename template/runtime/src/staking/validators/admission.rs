//! Validator admission as staking applies it: the validator set's rules (bans,
//! session keys, allowlist) plus the self-bond, which only staking knows.
//!
//! [`check`] is the one rule. Three places apply it:
//!
//! | Where | When | Why |
//! |---|---|---|
//! | `CheckValidatorCandidacy` | a `staking.validate` is submitted | nobody becomes a candidate without passing |
//! | [`ChillOnRemoval`] | the validator set removes or bans an account | admission changed after it became a candidate |
//! | [`AdmissionFilteredTargets`] | every election snapshot | what changed without an event: a slash below the minimum, purged keys, an expired ban, a mode switch, root's `sudo_as` |
//!
//! A candidacy the rule no longer admits keeps its candidate slot until anyone
//! ends it with `validatorSet.chill_inadmissible` ([`StakingCandidacy`]).
//!
//! `CheckValidatorCandidacy` also keeps the candidates within what the election
//! reads (`MaxTargets`), whatever governance sets `MaxValidatorsCount` to; a
//! snapshot taken over more (only root's `sudo_as` gets there) logs an error.
//!
//! The commission ceiling (staking's `MaxCommission`) is checked on the
//! commission a `staking.validate` offers, and again on the stored one in every
//! snapshot, so a candidacy above it is not electable. Candidates above a
//! lowered ceiling are clamped to it at the next session report
//! ([`super::commission`]); the snapshot check covers what that has not reached.

use crate::staking::{params::OPEN_MODE_MIN_SELF_BOND, register_reads};
use crate::{AccountId, Balance, Runtime, Staking, ValidatorSet};
use alloc::boxed::Box;
use core::marker::PhantomData;
use frame_election_provider_support::SortedListProvider;
use pallet_validator_set::{Admission, AdmissionMode};
use sp_runtime::Perbill;
use sp_staking::StakingInterface;

/// Why an account may not be a validator candidate. The codes are part of the
/// runtime's interface: the candidacy extension rejects with them and wallets
/// show them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Inadmissible {
	/// Not in the allowlist while admission is permissioned.
	NotApproved = 1,
	/// Under a ban.
	Banned = 2,
	/// No session keys registered.
	NoSessionKeys = 3,
	/// Self-bond below [`min_self_bond`].
	InsufficientSelfBond = 4,
	/// Commission above staking's `MaxCommission`.
	CommissionTooHigh = 5,
	/// No staking ledger: the account never bonded.
	NotBonded = 6,
	/// As many candidates as the election reads (`MaxTargets`); more would be
	/// dropped from its snapshot.
	TooManyCandidates = 7,
}

impl From<pallet_validator_set::Inadmissible> for Inadmissible {
	fn from(reason: pallet_validator_set::Inadmissible) -> Self {
		match reason {
			pallet_validator_set::Inadmissible::Banned => Self::Banned,
			pallet_validator_set::Inadmissible::NotApproved => Self::NotApproved,
			pallet_validator_set::Inadmissible::NoSessionKeys => Self::NoSessionKeys,
		}
	}
}

/// The self-bond a validator needs under `mode`: `MinValidatorBond`, never
/// below [`OPEN_MODE_MIN_SELF_BOND`] while admission is open.
pub fn min_self_bond(mode: AdmissionMode) -> Balance {
	let min = pallet_staking_async::MinValidatorBond::<Runtime>::get();
	match mode {
		AdmissionMode::Permissioned => min,
		AdmissionMode::Open => min.max(OPEN_MODE_MIN_SELF_BOND),
	}
}

/// Whether `stash` may be a validator candidate under `admission`.
pub fn check(admission: &Admission<Runtime>, stash: &AccountId) -> Result<(), Inadmissible> {
	admission.check(stash)?;
	let stake = <Staking as StakingInterface>::stake(stash).map_err(|_| Inadmissible::NotBonded)?;
	if stake.active < min_self_bond(admission.mode()) {
		return Err(Inadmissible::InsufficientSelfBond);
	}
	Ok(())
}

/// Whether the commission `stash` validates with is within `max`.
pub fn within_max_commission(stash: &AccountId, max: Perbill) -> bool {
	pallet_staking_async::Validators::<Runtime>::get(stash).commission <= max
}

/// Storage reads the snapshot filter makes per candidate: the ban, the session
/// keys, the bonded controller, the ledger, the minimum bond and the
/// commission. Counted by hand until a benchmark replaces it.
const READS_PER_CANDIDATE: u64 = 6;
/// Reads taking the admission snapshot: mode, allowlist, block number, the
/// commission ceiling and the candidate count.
const READS_PER_SNAPSHOT: u64 = 5;

fn admitted(inner: Box<dyn Iterator<Item = AccountId>>) -> Box<dyn Iterator<Item = AccountId>> {
	register_reads(READS_PER_SNAPSHOT);
	// The candidacy check keeps the count within the election's reach; past it
	// (root's `sudo_as`), candidates are cut in storage order. The cut comes
	// before the filter: staking stops at `MaxTargets` admitted candidates, so
	// rejected ones would otherwise be read without bound.
	let (candidates, max) = (
		pallet_staking_async::Validators::<Runtime>::count(),
		<Runtime as pallet_paged_election::Config>::MaxTargets::get(),
	);
	if candidates > max {
		log::error!(
			target: "runtime::staking",
			"{candidates} validator candidates; the election reads {max}, the rest are left out",
		);
	}
	let admission = ValidatorSet::admission();
	let ceiling = pallet_staking_async::MaxCommission::<Runtime>::get();
	Box::new(inner.take(max as usize).filter(move |who| {
		register_reads(READS_PER_CANDIDATE);
		check(&admission, who).is_ok() && within_max_commission(who, ceiling)
	}))
}

/// `pallet_staking_async::Config::TargetList`: `Inner`'s candidates, minus those
/// [`check`] rejects or whose commission is above staking's `MaxCommission` at
/// the time of the snapshot.
///
/// Only iteration filters. `count` stays `Inner`'s, an upper bound the
/// election sizes its snapshot with, and the bookkeeping calls pass through so
/// `Inner` stays consistent with staking's `Validators`.
pub struct AdmissionFilteredTargets<Inner>(PhantomData<Inner>);

impl<Inner> SortedListProvider<AccountId> for AdmissionFilteredTargets<Inner>
where
	Inner: SortedListProvider<AccountId>,
{
	type Error = Inner::Error;
	type Score = Inner::Score;

	fn range() -> (Self::Score, Self::Score) {
		Inner::range()
	}
	fn iter() -> Box<dyn Iterator<Item = AccountId>> {
		admitted(Inner::iter())
	}
	fn lock() {
		Inner::lock()
	}
	fn unlock() {
		Inner::unlock()
	}
	fn iter_from(start: &AccountId) -> Result<Box<dyn Iterator<Item = AccountId>>, Self::Error> {
		Inner::iter_from(start).map(admitted)
	}
	fn count() -> u32 {
		Inner::count()
	}
	fn contains(id: &AccountId) -> bool {
		Inner::contains(id)
	}
	fn on_insert(id: AccountId, score: Self::Score) -> Result<(), Self::Error> {
		Inner::on_insert(id, score)
	}
	fn on_update(id: &AccountId, score: Self::Score) -> Result<(), Self::Error> {
		Inner::on_update(id, score)
	}
	fn get_score(id: &AccountId) -> Result<Self::Score, Self::Error> {
		Inner::get_score(id)
	}
	fn on_increase(id: &AccountId, additional: Self::Score) -> Result<(), Self::Error> {
		Inner::on_increase(id, additional)
	}
	fn on_decrease(id: &AccountId, decreased: Self::Score) -> Result<(), Self::Error> {
		Inner::on_decrease(id, decreased)
	}
	fn on_remove(id: &AccountId) -> Result<(), Self::Error> {
		Inner::on_remove(id)
	}
	fn unsafe_regenerate(
		all: impl IntoIterator<Item = AccountId>,
		score_of: Box<dyn Fn(&AccountId) -> Option<Self::Score>>,
	) -> u32 {
		Inner::unsafe_regenerate(all, score_of)
	}
	fn unsafe_clear() {
		Inner::unsafe_clear()
	}
	#[cfg(feature = "try-runtime")]
	fn try_state() -> Result<(), sp_runtime::TryRuntimeError> {
		Inner::try_state()
	}
	#[cfg(feature = "runtime-benchmarks")]
	fn score_update_worst_case(who: &AccountId, is_increase: bool) -> Self::Score {
		Inner::score_update_worst_case(who, is_increase)
	}
}

/// `pallet_validator_set::Config::Candidacy`: a candidate that fails [`check`].
/// The election already skips it; `validatorSet.chill_inadmissible` lets anyone
/// end its candidacy, which would otherwise keep counting against the candidates
/// `MaxTargets` allows. A commission above a lowered `MaxCommission` is not a
/// reason: the next session report clamps it, and anyone ending those
/// candidacies first could shrink the next set.
pub struct StakingCandidacy;

impl pallet_validator_set::Candidacy<AccountId> for StakingCandidacy {
	fn is_inadmissible_candidate(who: &AccountId) -> bool {
		pallet_staking_async::Validators::<Runtime>::contains_key(who)
			&& check(&ValidatorSet::admission(), who).is_err()
	}
}

/// Stops an account's validator candidacy when the validator set removes or
/// bans it, instead of waiting for the next election to filter it out. A
/// nominator is left alone: losing the right to validate is no reason to stop
/// nominating.
pub struct ChillOnRemoval;

impl pallet_validator_set::OnValidatorRemoved<AccountId> for ChillOnRemoval {
	fn on_validator_removed(who: &AccountId) {
		if pallet_staking_async::Validators::<Runtime>::contains_key(who) {
			let _ = <Staking as StakingInterface>::chill(who);
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_removal_state(who: &AccountId) {
		use frame_support::traits::fungible::Mutate;
		let bond = pallet_staking_async::MinValidatorBond::<Runtime>::get().max(1);
		crate::Balances::set_balance(who, bond.saturating_mul(2));
		let _ = <Staking as StakingInterface>::bond(who, bond, who);
		let _ = Staking::validate(
			crate::RuntimeOrigin::signed(who.clone()),
			pallet_staking_async::ValidatorPrefs::default(),
		);
	}
}

/// `pallet_validator_set::Config::OpenModeGuard`: admission may open only once
/// `MinValidatorBond` already meets [`OPEN_MODE_MIN_SELF_BOND`], so the switch
/// cannot precede the bond it relies on. The floor applies in open mode
/// regardless ([`min_self_bond`]).
pub struct SelfBondFloor;

impl pallet_validator_set::OpenModeGuard for SelfBondFloor {
	fn can_open() -> bool {
		pallet_staking_async::MinValidatorBond::<Runtime>::get() >= OPEN_MODE_MIN_SELF_BOND
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_can_open() {
		pallet_staking_async::MinValidatorBond::<Runtime>::put(OPEN_MODE_MIN_SELF_BOND);
	}
}
