//! Benchmarks for `pallet-validator-set`'s calls.

use crate::*;
use crate::{
	Candidacy, OnValidatorRemoved, OpenModeGuard, ValidatorPrerequisites, traits::BenchmarkHelper,
};
use frame_benchmarking::v2::*;
use frame_support::traits::Get;
use frame_system::RawOrigin;

#[benchmarks]
mod benchmarks {
	use super::*;

	// ── add_validator ─────────────────────────────────────────────────────────

	/// Worst case: set already contains `MaxValidators - 1` entries (maximum
	/// BoundedVec scan before the push succeeds).
	#[benchmark]
	fn add_validator() {
		// Fill the set to MaxValidators - 1
		let max = T::MaxValidators::get();
		let existing: frame_support::BoundedVec<T::AccountId, T::MaxValidators> = (0..max - 1)
			.map(|i| account::<T::AccountId>("validator", i, 0))
			.collect::<sp_std::vec::Vec<_>>()
			.try_into()
			.expect("max - 1 < MaxValidators; qed");
		ApprovedValidators::<T>::put(existing);

		let new_validator: T::AccountId = account("new", 0, 0);
		// The extrinsic gates on session keys; register them for the target first.
		T::Prerequisites::setup_session_keys(&new_validator);

		#[extrinsic_call]
		add_validator(RawOrigin::Root, new_validator.clone());

		assert!(ApprovedValidators::<T>::get().contains(&new_validator));
	}

	// ── remove_validator ──────────────────────────────────────────────────────

	/// Worst case: the target validator is at the last position in the set
	/// (maximum linear scan over `MaxValidators` entries) **and** has dependent
	/// state for `OnValidatorRemoved` to clean up, so the hook's writes are
	/// measured rather than short-circuited.
	#[benchmark]
	fn remove_validator() {
		let max = T::MaxValidators::get();
		let mut validators: sp_std::vec::Vec<T::AccountId> = (0..max - 1)
			.map(|i| account::<T::AccountId>("validator", i, 0))
			.collect();
		let target: T::AccountId = account("target", 0, 0);
		validators.push(target.clone());

		T::BenchmarkHelper::set_active_validators(validators.clone());
		let bounded: frame_support::BoundedVec<T::AccountId, T::MaxValidators> = validators
			.try_into()
			.expect("max entries == MaxValidators; qed");
		ApprovedValidators::<T>::put(bounded);
		T::OnValidatorRemoved::setup_removal_state(&target);

		#[extrinsic_call]
		remove_validator(RawOrigin::Root, target.clone());

		assert!(!ApprovedValidators::<T>::get().contains(&target));
	}

	// ── set_min_author_version ───────────────────────────────────────────────

	/// Worst case: a full set, every validator counted toward the quorum, so the
	/// guard reads one `LastAuthorVersion` entry per validator.
	#[benchmark]
	fn set_min_author_version() {
		let max = T::MaxValidators::get();
		let validators: sp_std::vec::Vec<T::AccountId> = (0..max)
			.map(|i| account::<T::AccountId>("validator", i, 0))
			.collect();
		let min = NodeVersion::new(1, 0, 0);
		let now = frame_system::Pallet::<T>::block_number();
		for v in &validators {
			LastAuthorVersion::<T>::insert(v, (min, now));
		}
		T::BenchmarkHelper::set_active_validators(validators.clone());
		let bounded: frame_support::BoundedVec<T::AccountId, T::MaxValidators> = validators
			.try_into()
			.expect("max entries == MaxValidators; qed");
		ApprovedValidators::<T>::put(bounded);

		#[extrinsic_call]
		set_min_author_version(RawOrigin::Root, Some(min));

		assert_eq!(MinAuthorVersion::<T>::get(), Some(min));
	}

	// ── note_author_version ──────────────────────────────────────────────────

	/// Worst case: a minimum is set, so the declared version is compared too.
	/// The runtime's `FindAuthor` needs an Aura pre-digest a benchmark block
	/// lacks, so the author lookup and the `LastAuthorVersion` write are not
	/// measured; the estimated weight accounts for them.
	#[benchmark]
	fn note_author_version() {
		MinAuthorVersion::<T>::put(NodeVersion::new(0, 0, 1));

		#[extrinsic_call]
		note_author_version(RawOrigin::None, NodeVersion::new(1, 0, 0));

		assert!(AuthorVersionNoted::<T>::get());
	}

	// ── Admission ────────────────────────────────────────────────────────────

	/// Worst case: opening, which also consults the runtime's guard.
	#[benchmark]
	fn set_admission_mode() {
		T::OpenModeGuard::setup_can_open();

		#[extrinsic_call]
		set_admission_mode(RawOrigin::Root, AdmissionMode::Open);

		assert_eq!(Mode::<T>::get(), AdmissionMode::Open);
	}

	/// Worst case: the account has dependent state, so the removal hook's
	/// cleanup (a staking chill in the runtime) is measured.
	#[benchmark]
	fn ban_validator() {
		let target: T::AccountId = account("target", 0, 0);
		T::OnValidatorRemoved::setup_removal_state(&target);

		#[extrinsic_call]
		ban_validator(RawOrigin::Root, target.clone(), BanTerm::Permanent);

		assert!(Pallet::<T>::is_banned(&target));
	}

	#[benchmark]
	fn unban_validator() {
		let target: T::AccountId = account("target", 0, 0);
		Bans::<T>::insert(&target, BanTerm::Permanent);

		#[extrinsic_call]
		unban_validator(RawOrigin::Root, target.clone());

		assert!(!Pallet::<T>::is_banned(&target));
	}

	/// A candidate the runtime no longer admits: the removal hook's setup
	/// bonds and offers it as a validator, without session keys.
	#[benchmark]
	fn chill_inadmissible() {
		let target: T::AccountId = account("target", 0, 0);
		let caller: T::AccountId = whitelisted_caller();
		T::OnValidatorRemoved::setup_removal_state(&target);
		assert!(T::Candidacy::is_inadmissible_candidate(&target));

		#[extrinsic_call]
		chill_inadmissible(RawOrigin::Signed(caller), target.clone());

		assert!(!T::Candidacy::is_inadmissible_candidate(&target));
	}

	impl_benchmark_test_suite!(
		Pallet,
		crate::tests::mock::ExtBuilder::default().build(),
		crate::tests::mock::Test
	);
}
