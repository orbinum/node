//! # Pallet Paged Election
//!
//! Staking's election, computed on-chain: sequential Phragmén over a paged
//! snapshot, spread across blocks within a weight budget, with no off-chain
//! miner. It implements [`ElectionProvider`] for `pallet-staking-async`.
//!
//! ## Flow
//!
//! `start` arms the election; each block's `on_poll` then runs as many steps
//! as fit [`Config::RoundBudget`] of the block:
//!
//! 1. **Snapshot.** The targets and the number of seats, then one voter page
//!    per step, from the most significant page down to 0, as staking pages
//!    them. Votes become candidate indices; votes for non-candidates, repeats
//!    and voters without stake or valid votes are dropped, as upstream does.
//! 2. **Rounds.** Each round elects the candidate with the lowest score, then
//!    passes over the voter pages applying the new winner's score as the load
//!    of the voters approving it. Only per-candidate sums and the winners'
//!    scores persist; a page none of whose voters approve the winner is
//!    skipped unread.
//! 3. **Export.** Once done, `status` reports ready and staking fetches the
//!    pages with `elect`, most significant first; each page's supports are
//!    rebuilt from the winners' scores. `elect(0)` clears everything.
//!
//! ## Exactness
//!
//! [`phragmen`] reproduces `sp_npos_elections::seq_phragmen`'s integer
//! arithmetic (without balancing): the same winners in the same order, and the
//! same stake on every edge, so each winner's total equals upstream's backed
//! stake exactly. Scores saturate where upstream's do; when one does,
//! [`Event::ScoreSaturated`] reports it.
//!
//! ## Safety
//!
//! - Every step is priced with [`WeightInfo`] before it runs and runs only if
//!   it fits; [`ElectionProvider::duration`] is derived from the same prices.
//! - A failure ([`FailReason`]) makes every page fetch error, so staking keeps
//!   its validators; page 0 clears the state. [`Pallet::abort`] fails a stuck
//!   election, and clears a failed one, until staking fetches a page.
//! - Storage is bounded; nothing panics.
//!
//! ## Layout
//!
//! - [`types`]: the snapshot and the election's progress.
//! - `engine`: the hooks' work, one module per concern (snapshot, rounds,
//!   export, invariants) and the cost model they share; [`phragmen`], the
//!   arithmetic as pure functions; `provider`, the [`ElectionProvider`]
//!   interface.
//! - `benchmarking`: the benchmarks and the [`weights`] they produce.
//! - `tests`: the mock runtime and the tests.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod types;

mod benchmarking;
mod engine;

#[cfg(test)]
mod tests;

pub use benchmarking::weights;
pub use engine::phragmen;

use frame_election_provider_support::ElectionDataProvider;
use frame_support::BoundedVec;

pub use frame_election_provider_support::ElectionProvider;
pub use pallet::*;
pub use types::{
	Candidate, ElectionError, ElectionMeta, FailReason, PageInfo, Phase, SnapshotVoter, TargetIndex,
};
pub use weights::WeightInfo;

pub(crate) const LOG_TARGET: &str = "runtime::paged-election";

/// Votes a voter may cast, as staking provides them.
pub type MaxVotesOf<T> = <<T as Config>::DataProvider as ElectionDataProvider>::MaxVotesPerVoter;

pub type VoterOf<T> = SnapshotVoter<<T as frame_system::Config>::AccountId, MaxVotesOf<T>>;

pub type VoterPageOf<T> = BoundedVec<VoterOf<T>, <T as Config>::VoterSnapshotPerBlock>;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_election_provider_support::{ExtendedBalance, PageIndex};
	use frame_support::{pallet_prelude::*, weights::WeightMeter};
	use frame_system::pallet_prelude::*;
	use sp_runtime::Perbill;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Staking: targets, paged voters and the number of seats.
		type DataProvider: ElectionDataProvider<AccountId = Self::AccountId, BlockNumber = BlockNumberFor<Self>>;

		/// Voter pages in the snapshot.
		#[pallet::constant]
		type Pages: Get<PageIndex>;

		/// Most voters in a page.
		#[pallet::constant]
		type VoterSnapshotPerBlock: Get<u32>;

		/// Most targets in the snapshot; at most `2^16`.
		#[pallet::constant]
		type MaxTargets: Get<u32>;

		/// Most winners, in a page and overall: staking's seats may not exceed it.
		#[pallet::constant]
		type MaxWinnersPerPage: Get<u32>;

		/// Most backers of a winner in a page; at least `VoterSnapshotPerBlock`.
		#[pallet::constant]
		type MaxBackersPerWinner: Get<u32>;

		/// Most backers of a winner over all pages; at least every voter.
		#[pallet::constant]
		type MaxBackersPerWinnerFinal: Get<u32>;

		/// Share of a block's weight the election may use in `on_poll`.
		#[pallet::constant]
		type RoundBudget: Get<Perbill>;

		/// May abort the election.
		type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		type WeightInfo: WeightInfo;
	}

	/// What the next step does.
	#[pallet::storage]
	pub type CurrentPhase<T> = StorageValue<_, Phase, ValueQuery>;

	/// The running election's bookkeeping.
	#[pallet::storage]
	pub type Meta<T: Config> = StorageValue<_, ElectionMeta<BlockNumberFor<T>>, OptionQuery>;

	/// Targets, deduplicated, in staking's order.
	#[pallet::storage]
	pub type Targets<T: Config> =
		StorageValue<_, BoundedVec<T::AccountId, T::MaxTargets>, ValueQuery>;

	/// Each target's approval and score sum, by target index.
	#[pallet::storage]
	pub type Candidates<T: Config> =
		StorageValue<_, BoundedVec<Candidate, T::MaxTargets>, ValueQuery>;

	/// Winners in election order: target index and winning score.
	#[pallet::storage]
	pub type Winners<T: Config> = StorageValue<
		_,
		BoundedVec<(TargetIndex, ExtendedBalance), T::MaxWinnersPerPage>,
		ValueQuery,
	>;

	/// Voter pages; an empty page is not stored.
	#[pallet::storage]
	pub type VoterPages<T: Config> =
		StorageMap<_, Twox64Concat, PageIndex, VoterPageOf<T>, OptionQuery>;

	/// Each stored voter page's size and approvers per target.
	#[pallet::storage]
	pub type PageInfos<T: Config> =
		StorageMap<_, Twox64Concat, PageIndex, PageInfo<T::MaxTargets>, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Staking started an election.
		ElectionStarted,
		/// The snapshot is complete.
		SnapshotTaken {
			targets: u32,
			voters: u32,
			edges: u32,
			pages: u32,
			to_elect: u32,
		},
		/// Every winner is elected, `blocks` after the start; staking may fetch
		/// the pages.
		ElectionDone {
			winners: u32,
			blocks: BlockNumberFor<T>,
		},
		/// Staking fetched a page of supports.
		PageExported {
			page: PageIndex,
			winners: u32,
			backers: u32,
		},
		/// The election failed; staking's page fetches error and it keeps its
		/// validators.
		ElectionFailed { reason: FailReason },
		/// A score saturated at `u128::MAX` in `round`, as upstream's would:
		/// rankings among saturated candidates fall back to target order.
		ScoreSaturated { round: u32 },
		/// Governance cleared a failed election.
		Cleared,
		/// Staking's planned era `era` could not start (its election failed or
		/// its set was dropped), so the runtime reset the plan: the session
		/// report that follows plans it again with a new election.
		EraPlanReset { era: u32 },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// No election is running.
		NotOngoing,
		/// Staking already fetched a page: the rest follow, and page 0 clears
		/// the election.
		AlreadyFetching,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_poll(now: BlockNumberFor<T>, meter: &mut WeightMeter) {
			Self::poll(now, meter);
		}

		fn integrity_test() {
			Self::check_parameters();
		}

		#[cfg(feature = "try-runtime")]
		fn try_state(_: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
			Self::do_try_state()
		}

		/// An upgrade may change the bounds the stored snapshot was taken with.
		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<alloc::vec::Vec<u8>, sp_runtime::TryRuntimeError> {
			frame_support::ensure!(
				CurrentPhase::<T>::get() == Phase::Off,
				"upgrade while an election runs or waits to be fetched"
			);
			Ok(alloc::vec::Vec::new())
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Fails an election still computing, or done before staking fetched a
		/// page, so staking's page fetches error and it keeps its validators;
		/// clears a failed one staking has not started fetching. Refused once
		/// staking fetched a page: aborting then would seat the winners of the
		/// pages it already took, and clearing would leave it waiting for the
		/// rest forever.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::abort().saturating_add(Pallet::<T>::clear_weight()))]
		pub fn abort(origin: OriginFor<T>) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;
			let phase = CurrentPhase::<T>::get();
			ensure!(phase != Phase::Off, Error::<T>::NotOngoing);
			ensure!(
				Meta::<T>::get().is_none_or(|meta| meta.fetched == 0),
				Error::<T>::AlreadyFetching
			);
			match phase {
				Phase::Failed(_) => {
					Self::clear();
					Self::deposit_event(Event::Cleared);
				}
				_ => {
					Self::fail(FailReason::Aborted);
				}
			}
			Ok(())
		}
	}
}
