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
use frame_system::RawOrigin;
use sp_core::H160;

#[benchmarks]
mod benchmarks {
	use super::*;

	// ── Helpers ──────────────────────────────────────────────────────────────

	fn evm_address_for(seed: u64) -> H160 {
		H160::from_low_u64_be(seed)
	}

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

	/// Worst case: two storage writes + event deposit.
	///
	/// `register_relayer` is gated by `ManageOrigin` (sudo/governance).
	/// We call it with `RawOrigin::Root` which always satisfies that bound.
	#[benchmark]
	fn register_relayer() {
		let who: T::AccountId = whitelisted_caller();
		let evm = evm_address_for(0xA11CE);

		#[extrinsic_call]
		register_relayer(RawOrigin::Root, who.clone(), evm);

		assert_eq!(RelayerRegistry::<T>::get(evm), Some(who));
	}

	// ── unregister_relayer ───────────────────────────────────────────────────

	/// Worst case: two storage removals + event.
	/// Pre-condition: caller has a registered EVM address.
	#[benchmark]
	fn unregister_relayer() {
		let caller: T::AccountId = whitelisted_caller();
		let evm = evm_address_for(0xA11CE);

		// Pre-register so unregister has real work to do.
		RelayerRegistry::<T>::insert(evm, caller.clone());
		RelayerByAccount::<T>::insert(caller.clone(), evm);

		#[extrinsic_call]
		unregister_relayer(RawOrigin::Signed(caller.clone()));

		assert!(!RelayerRegistry::<T>::contains_key(evm));
		assert!(!RelayerByAccount::<T>::contains_key(&caller));
	}

	// ── Benchmark test suite ─────────────────────────────────────────────────

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test,);
}
