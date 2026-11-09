//! Weights for pallet_auto_payout.
//!
//! Placeholder until `scripts/benchmarks/run_benchmarks.sh --group staking`
//! regenerates this file on the reference hardware. The hooks do not use these:
//! they price each page with staking's own weights and count their storage
//! accesses with `DbWeight`.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for pallet_auto_payout.
pub trait WeightInfo {
	fn set_limits() -> Weight;
	fn pause() -> Weight;
	fn resume() -> Weight;
}

/// Weights for pallet_auto_payout using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: `AutoPayout::Limits` (r:0 w:1)
	fn set_limits() -> Weight {
		Weight::from_parts(15_000_000, 0)
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `AutoPayout::Paused` (r:1 w:1)
	fn pause() -> Weight {
		// Plus the expiry check (the era being paid, the queue and staking's
		// active and planned eras), estimated until the next benchmark run.
		Weight::from_parts(10_000_000, 1489)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `AutoPayout::Paused` (r:1 w:1)
	fn resume() -> Weight {
		Weight::from_parts(10_000_000, 1489)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
}

// For backwards compatibility and tests.
impl WeightInfo for () {
	fn set_limits() -> Weight {
		Weight::from_parts(15_000_000, 0)
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	fn pause() -> Weight {
		// Plus the expiry check (the era being paid, the queue and staking's
		// active and planned eras), estimated until the next benchmark run.
		Weight::from_parts(10_000_000, 1489)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	fn resume() -> Weight {
		Weight::from_parts(10_000_000, 1489)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
}
