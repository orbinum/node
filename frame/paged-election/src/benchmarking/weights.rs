//! Weights for pallet_paged_election.
//!
//! PLACEHOLDER: conservative estimates, several times the native timings of the
//! `report` test, until `scripts/benchmarks/run_benchmarks.sh` regenerates this
//! file on the reference hardware with staking as the data provider. The
//! snapshot steps also price staking's reads of each target and voter.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for pallet_paged_election.
pub trait WeightInfo {
	/// The target snapshot with `t` targets.
	fn snapshot_targets(t: u32, ) -> Weight;
	/// A voter page snapshot with `v` voters of full votes.
	fn snapshot_voters(v: u32, ) -> Weight;
	/// Electing a winner among `t` targets.
	fn select_winner(t: u32, ) -> Weight;
	/// Applying a winner to a page: `n` voters scanned, `a` approving it.
	fn apply_page(n: u32, a: u32, ) -> Weight;
	/// Staking fetching a page of `v` voters of full votes, storing it included.
	fn export_page(v: u32, ) -> Weight;
	/// Aborting an election.
	fn abort() -> Weight;
}

/// Weights for pallet_paged_election using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: `Staking::Validators` (r:t w:0), `Staking::ValidatorCount` (r:1 w:0)
	/// Storage: `PagedElection::Targets`, `Candidates`, `Meta`, `CurrentPhase` (r:1 w:4)
	fn snapshot_targets(t: u32, ) -> Weight {
		Weight::from_parts(100_000_000, 4_000)
			.saturating_add(Weight::from_parts(20_000_000, 600).saturating_mul(t.into()))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(t.into())))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
	/// Storage: `VoterList::ListNodes`, `Staking::Nominators`, `Staking::Validators`, `Staking::Bonded`, `Staking::Ledger` (r:5v w:0)
	/// Storage: `PagedElection::VoterPages`, `PageInfos`, `Candidates`, `Targets`, `Meta`, `CurrentPhase` (r:3 w:5)
	fn snapshot_voters(v: u32, ) -> Weight {
		Weight::from_parts(300_000_000, 30_000)
			.saturating_add(Weight::from_parts(65_000_000, 3_000).saturating_mul(v.into()))
			.saturating_add(T::DbWeight::get().reads(8_u64))
			.saturating_add(T::DbWeight::get().reads((5_u64).saturating_mul(v.into())))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `PagedElection::Candidates`, `Winners`, `Meta`, `CurrentPhase` (r:3 w:3)
	fn select_winner(t: u32, ) -> Weight {
		Weight::from_parts(50_000_000, 12_000)
			.saturating_add(Weight::from_parts(1_000_000, 40).saturating_mul(t.into()))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// Storage: `PagedElection::PageInfos`, `VoterPages`, `Candidates`, `Winners`, `CurrentPhase` (r:4 w:2)
	fn apply_page(n: u32, a: u32, ) -> Weight {
		Weight::from_parts(300_000_000, 30_000)
			.saturating_add(Weight::from_parts(500_000, 75).saturating_mul(n.into()))
			.saturating_add(Weight::from_parts(2_000_000, 75).saturating_mul(a.into()))
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Staking's `fetch_page`: this page's supports, and staking storing them as
	/// exposures (r:v w:2v).
	/// Storage: `PagedElection::CurrentPhase`, `Targets`, `Winners`, `VoterPages` (r:4 w:0)
	fn export_page(v: u32, ) -> Weight {
		Weight::from_parts(300_000_000, 20_000)
			.saturating_add(Weight::from_parts(10_000_000, 200).saturating_mul(v.into()))
			.saturating_add(T::DbWeight::get().reads(8_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(v.into())))
			.saturating_add(T::DbWeight::get().writes((2_u64).saturating_mul(v.into())))
	}
	/// Storage: `PagedElection::CurrentPhase` (r:1 w:1)
	fn abort() -> Weight {
		Weight::from_parts(50_000_000, 1_500)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
}

// For backwards compatibility and tests.
impl WeightInfo for () {
	fn snapshot_targets(t: u32, ) -> Weight {
		Weight::from_parts(100_000_000, 4_000)
			.saturating_add(Weight::from_parts(20_000_000, 600).saturating_mul(t.into()))
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().reads((1_u64).saturating_mul(t.into())))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}
	fn snapshot_voters(v: u32, ) -> Weight {
		Weight::from_parts(300_000_000, 30_000)
			.saturating_add(Weight::from_parts(65_000_000, 3_000).saturating_mul(v.into()))
			.saturating_add(RocksDbWeight::get().reads(8_u64))
			.saturating_add(RocksDbWeight::get().reads((5_u64).saturating_mul(v.into())))
			.saturating_add(RocksDbWeight::get().writes(5_u64))
	}
	fn select_winner(t: u32, ) -> Weight {
		Weight::from_parts(50_000_000, 12_000)
			.saturating_add(Weight::from_parts(1_000_000, 40).saturating_mul(t.into()))
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
	}
	fn apply_page(n: u32, a: u32, ) -> Weight {
		Weight::from_parts(300_000_000, 30_000)
			.saturating_add(Weight::from_parts(500_000, 75).saturating_mul(n.into()))
			.saturating_add(Weight::from_parts(2_000_000, 75).saturating_mul(a.into()))
			.saturating_add(RocksDbWeight::get().reads(4_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	fn export_page(v: u32, ) -> Weight {
		Weight::from_parts(300_000_000, 20_000)
			.saturating_add(Weight::from_parts(10_000_000, 200).saturating_mul(v.into()))
			.saturating_add(RocksDbWeight::get().reads(8_u64))
			.saturating_add(RocksDbWeight::get().reads((1_u64).saturating_mul(v.into())))
			.saturating_add(RocksDbWeight::get().writes((2_u64).saturating_mul(v.into())))
	}
	fn abort() -> Weight {
		Weight::from_parts(50_000_000, 1_500)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
}
