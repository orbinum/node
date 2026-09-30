//! Benchmarks for pallet-relayer.
//!
//! Run with:
//! ```bash
//! cargo build --release --features runtime-benchmarks
//! ./target/release/orbinum-node benchmark pallet \
//!   --chain=dev \
//!   --pallet=pallet_relayer \
//!   --extrinsic='*' \
//!   --steps=50 \
//!   --repeat=20 \
//!   --output=frame/relayer/src/weights.rs \
//!   --template=./scripts/frame-weight-template.hbs
//! ```

use super::*;
use frame_benchmarking::v2::*;
use frame_support::traits::Get;
use frame_system::{RawOrigin, pallet_prelude::BlockNumberFor};
use pallet_validator_set::ValidatorSetInterface;
use sp_core::H160;

#[benchmarks]
mod benchmarks {
	use super::*;

	// ── set_min_relay_fee ────────────────────────────────────────────────────

	/// Worst case: single storage write + event deposit.
	#[benchmark]
	fn set_min_relay_fee() {
		#[extrinsic_call]
		set_min_relay_fee(RawOrigin::Root, 999_999u128);

		assert_eq!(MinRelayFee::<T>::get(), 999_999u128);
	}

	// ── set_allowed_selectors ────────────────────────────────────────────────

	/// Worst case: full list of `MaxAllowedSelectors` entries.
	#[benchmark]
	fn set_allowed_selectors(n: Linear<0, { T::MaxAllowedSelectors::get() }>) {
		let selectors: sp_std::vec::Vec<[u8; 4]> = (0..n).map(|i| i.to_le_bytes()).collect();

		#[extrinsic_call]
		set_allowed_selectors(RawOrigin::Root, selectors);

		assert_eq!(AllowedSelectors::<T>::get().len() as u32, n);
	}

	// ── register_relayer ─────────────────────────────────────────────────────

	/// Worst case: validator-set lookup + two storage writes + event deposit.
	///
	/// `register_relayer` is gated on membership of the active validator set,
	/// so the caller has to be put there first.
	#[benchmark]
	fn register_relayer() {
		let who: T::AccountId = whitelisted_caller();
		T::ValidatorSet::setup_validator(&who);
		// A fixed key whose signature over the binding digest is recomputed here,
		// so the benchmark exercises the real ECDSA recovery path.
		let (evm, signature) = crate::test_signing::signed_binding::<T>(&who);

		#[extrinsic_call]
		register_relayer(RawOrigin::Signed(who.clone()), evm, signature);

		assert_eq!(RelayerRegistry::<T>::get(evm), Some(who));
	}

	// ── unregister_relayer ───────────────────────────────────────────────────

	/// Worst case: two storage removals + event.
	/// Pre-condition: caller has a registered EVM address.
	#[benchmark]
	fn unregister_relayer() {
		let caller: T::AccountId = whitelisted_caller();
		let evm = H160::from_low_u64_be(0xA11CE);

		// Pre-register so unregister has real work to do.
		RelayerRegistry::<T>::insert(evm, caller.clone());
		RelayerByAccount::<T>::insert(caller.clone(), evm);

		#[extrinsic_call]
		unregister_relayer(RawOrigin::Signed(caller.clone()));

		assert!(!RelayerRegistry::<T>::contains_key(evm));
		assert!(!RelayerByAccount::<T>::contains_key(&caller));
	}

	// ── on_initialize: prune_relay_commits ───────────────────────────────────

	/// `r` validators with an index entry expiring now, `n` commits spread
	/// over them. Ranges are the runtime's `MaxValidators` (32) and 32 ×
	/// `MaxCommitsPerRelayerPerBlock` (64); a benchmark range must be a literal.
	#[benchmark]
	fn prune_relay_commits(r: Linear<0, 32>, n: Linear<0, 2048>) {
		let recorded_at: BlockNumberFor<T> = 1u32.into();
		let expires_at = recorded_at + T::CommitTtl::get();
		let validators: sp_std::vec::Vec<T::AccountId> =
			(0..r.max(1)).map(|i| account("validator", i, 0)).collect();
		for who in validators.iter().take(r as usize) {
			CommitsByRelayer::<T>::insert(expires_at, who, frame_support::BoundedVec::default());
		}
		for i in 0..n {
			let commit = sp_core::H256::from_low_u64_be(i as u64 + 1);
			RelayCommits::<T>::insert(
				commit,
				RelayCommit {
					recorded_at,
					expires_at,
				},
			);
			let who = &validators[(i % r.max(1)) as usize];
			CommitsByRelayer::<T>::mutate(expires_at, who, |index| {
				let _ = index.try_push(commit);
			});
		}

		#[block]
		{
			<Pallet<T> as frame_support::traits::Hooks<BlockNumberFor<T>>>::on_initialize(
				expires_at,
			);
		}

		assert_eq!(CommitsByRelayer::<T>::iter_prefix(expires_at).count(), 0);
	}

	// ── Benchmark test suite ─────────────────────────────────────────────────

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test,);
}
