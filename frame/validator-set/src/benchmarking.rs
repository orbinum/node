//! Benchmarks for `pallet-validator-set`.
//!
//! Run with:
//! ```bash
//! cargo build --release --features runtime-benchmarks
//! ./target/release/orbinum-node benchmark pallet \
//!   --chain=dev \
//!   --pallet=pallet_validator_set \
//!   --extrinsic='*' \
//!   --steps=50 \
//!   --repeat=20 \
//!   --output=frame/validator-set/src/weights.rs \
//!   --template=./scripts/frame-weight-template.hbs
//! ```

use super::*;
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

		#[extrinsic_call]
		add_validator(RawOrigin::Root, new_validator.clone());

		assert!(ApprovedValidators::<T>::get().contains(&new_validator));
	}

	// ── remove_validator ──────────────────────────────────────────────────────

	/// Worst case: the target validator is at the last position in the set
	/// (maximum linear scan over `MaxValidators` entries).
	#[benchmark]
	fn remove_validator() {
		let max = T::MaxValidators::get();
		let mut validators: sp_std::vec::Vec<T::AccountId> = (0..max - 1)
			.map(|i| account::<T::AccountId>("validator", i, 0))
			.collect();
		let target: T::AccountId = account("target", 0, 0);
		validators.push(target.clone());

		let bounded: frame_support::BoundedVec<T::AccountId, T::MaxValidators> = validators
			.try_into()
			.expect("max entries == MaxValidators; qed");
		ApprovedValidators::<T>::put(bounded);

		#[extrinsic_call]
		remove_validator(RawOrigin::Root, target.clone());

		assert!(!ApprovedValidators::<T>::get().contains(&target));
	}

	impl_benchmark_test_suite!(
		Pallet,
		crate::mock::ExtBuilder::default().build(),
		crate::mock::Test
	);
}
