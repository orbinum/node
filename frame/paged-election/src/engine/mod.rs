// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hooks' work, one concern per module: taking the snapshot
//! ([`snapshot`]), electing winners and applying their loads ([`rounds`]),
//! rebuilding a page's supports ([`export`]) and the invariants (`invariants`,
//! for `try_state` and tests), on the arithmetic of [`phragmen`]; `provider`
//! serves the result to staking. This module holds the step loop and the cost
//! model they share, from which [`Pallet::duration_bound`] is derived.

mod export;
#[cfg(any(feature = "try-runtime", test))]
mod invariants;
pub mod phragmen;
mod provider;
mod rounds;
mod snapshot;

use crate::{
	Candidates, Config, CurrentPhase, Event, FailReason, MaxVotesOf, Meta, PageInfos, Pallet,
	Phase, Targets, VoterPages, WeightInfo, Winners,
};
use frame_election_provider_support::PageIndex;
use frame_support::{
	traits::Get,
	weights::{RuntimeDbWeight, Weight, WeightMeter},
};
use frame_system::pallet_prelude::BlockNumberFor;

impl<T: Config> Pallet<T> {
	pub(crate) fn db() -> RuntimeDbWeight {
		T::DbWeight::get()
	}

	/// The most the election spends in a block.
	pub fn budget() -> Weight {
		T::RoundBudget::get() * T::BlockWeights::get().max_block
	}

	pub(crate) fn msp() -> PageIndex {
		T::Pages::get().saturating_sub(1)
	}

	/// Runs steps while they fit the budget and what the block has left.
	pub(crate) fn poll(now: BlockNumberFor<T>, meter: &mut WeightMeter) {
		let mut ours = WeightMeter::with_limit(Self::budget().min(meter.remaining()));
		if ours.try_consume(Self::db().reads(1)).is_err() {
			return;
		}
		let mut phase = CurrentPhase::<T>::get();
		while let Some(next) = Self::step(now, phase, &mut ours) {
			phase = next;
		}
		meter.consume(ours.consumed());
	}

	/// Runs `phase`'s step if it fits `meter` and returns the next phase.
	pub(crate) fn step(
		now: BlockNumberFor<T>,
		phase: Phase,
		meter: &mut WeightMeter,
	) -> Option<Phase> {
		match phase {
			Phase::Off | Phase::Done | Phase::Failed(_) => None,
			Phase::Targets => Self::snapshot_targets(meter),
			Phase::Voters(page) => Self::snapshot_voters(page, meter),
			Phase::Select => Self::select(now, meter),
			Phase::Apply { page, winner } => Self::apply(page, winner, meter),
		}
	}

	/// Moves to [`Phase::Failed`]; the state stays until page 0 is fetched.
	pub(crate) fn fail(reason: FailReason) -> Phase {
		log::warn!(target: crate::LOG_TARGET, "election failed: {reason:?}");
		let phase = Phase::Failed(reason);
		CurrentPhase::<T>::put(phase);
		Self::deposit_event(Event::ElectionFailed { reason });
		phase
	}

	/// Removes every trace of the election.
	pub(crate) fn clear() {
		CurrentPhase::<T>::kill();
		Meta::<T>::kill();
		Targets::<T>::kill();
		Candidates::<T>::kill();
		Winners::<T>::kill();
		// Keys are pages: at most `Pages` of each, unless an upgrade lowered it
		// mid-election, so no limit.
		let _ = VoterPages::<T>::clear(u32::MAX, None);
		let _ = PageInfos::<T>::clear(u32::MAX, None);
	}

	pub(crate) fn clear_weight() -> Weight {
		Self::db().writes(5u64.saturating_add(2u64.saturating_mul(T::Pages::get().into())))
	}

	/// Staking's fetch of one page, the clearing after page 0 included.
	pub fn export_weight() -> Weight {
		T::WeightInfo::export_page(T::VoterSnapshotPerBlock::get())
			.saturating_add(Self::clear_weight())
	}

	/// An apply step on a page none of whose voters approve the winner.
	pub(crate) fn skip_weight() -> Weight {
		Self::db().reads_writes(1, 1)
	}

	/// What a block spends besides steps: the phase read and one look at a
	/// page that did not fit.
	pub(crate) fn block_overhead() -> Weight {
		Self::db().reads(2)
	}

	/// The heaviest snapshot step, as priced before it runs.
	pub(crate) fn snapshot_step() -> Weight {
		T::WeightInfo::snapshot_targets(T::MaxTargets::get()).max(T::WeightInfo::snapshot_voters(
			T::VoterSnapshotPerBlock::get(),
		))
	}

	/// The heaviest round step: an apply cost is linear in its two counts,
	/// which sum to at most a page, so it peaks at an end.
	pub(crate) fn round_step() -> Weight {
		let page = T::VoterSnapshotPerBlock::get();
		T::WeightInfo::select_winner(T::MaxTargets::get())
			.max(T::WeightInfo::apply_page(page, 0))
			.max(T::WeightInfo::apply_page(0, page))
			.max(Self::skip_weight())
	}

	/// The most blocks from `start` until `status` reports ready, if each
	/// block's `on_poll` gets the whole budget. Derived from the step prices:
	///
	/// - Snapshot: `1 + Pages` steps, each at most [`Self::snapshot_step`], so
	///   `k = ⌊(budget − overhead) / step⌋` of them fit each block.
	/// - Rounds: `w = min(MaxWinnersPerPage, MaxTargets)` selections and a pass
	///   over the pages after each but the last. With `apply = c₀ + cₙ·n +
	///   cₐ·a` (`n` voters scanned, `a` approving the winner), a voter is
	///   scanned in each of the `w − 1` passes and approves at most
	///   `m = min(MaxVotes, w − 1)` winners, so the passes cost at most
	///   `(w−1)·Pages·c₀ + V·(w−1)·cₙ + V·m·max(cₐ − cₙ, 0)`, `V` every voter.
	///   A block stops only when the next step, at most
	///   [`Self::round_step`], does not fit one dimension, so it spent more
	///   than `budget − overhead − step` there: per dimension, at most
	///   `⌈work / (budget − overhead − step)⌉` blocks stop on it, plus the
	///   last.
	///
	/// Saturates at `u32::MAX` when a step cannot fit the budget.
	pub fn duration_bound() -> u32 {
		let usable = Self::budget().saturating_sub(Self::block_overhead());
		let pages = u64::from(T::Pages::get());

		let step = Self::snapshot_step();
		let Some(per_block) = [
			(step.ref_time(), usable.ref_time()),
			(step.proof_size(), usable.proof_size()),
		]
		.into_iter()
		.filter_map(|(s, u)| u.checked_div(s))
		.min()
		.filter(|&k| k > 0) else {
			return u32::MAX;
		};
		let snapshot = pages.saturating_add(1).div_ceil(per_block);

		let winners = T::MaxWinnersPerPage::get().min(T::MaxTargets::get());
		let passes = u64::from(winners.saturating_sub(1));
		let voters = pages.saturating_mul(T::VoterSnapshotPerBlock::get().into());
		let approved = u64::from(MaxVotesOf::<T>::get()).min(passes);
		let base = T::WeightInfo::apply_page(0, 0);
		let c0 = base.max(Self::skip_weight());
		let cn = T::WeightInfo::apply_page(1, 0).saturating_sub(base);
		let ca = T::WeightInfo::apply_page(0, 1).saturating_sub(base);
		let work = T::WeightInfo::select_winner(T::MaxTargets::get())
			.saturating_mul(winners.into())
			.saturating_add(c0.saturating_mul(passes.saturating_mul(pages)))
			.saturating_add(cn.saturating_mul(voters.saturating_mul(passes)))
			.saturating_add(
				ca.saturating_sub(cn)
					.saturating_mul(voters.saturating_mul(approved)),
			);
		let room = usable.saturating_sub(Self::round_step());
		let mut rounds = 1u64;
		for (w, r) in [
			(work.ref_time(), room.ref_time()),
			(work.proof_size(), room.proof_size()),
		] {
			if w == 0 {
				continue;
			}
			if r == 0 {
				return u32::MAX;
			}
			rounds = rounds.saturating_add(w.div_ceil(r));
		}

		u32::try_from(snapshot.saturating_add(rounds)).unwrap_or(u32::MAX)
	}

	/// Panics on parameters the election cannot work with.
	pub(crate) fn check_parameters() {
		let pages = T::Pages::get();
		let page = T::VoterSnapshotPerBlock::get();
		assert!(pages > 0, "Pages must be positive");
		assert!(page > 0, "VoterSnapshotPerBlock must be positive");
		assert!(
			MaxVotesOf::<T>::get() > 0,
			"MaxVotesPerVoter must be positive"
		);
		assert!(
			T::MaxTargets::get() > 0
				&& T::MaxTargets::get() <= u32::from(crate::TargetIndex::MAX) + 1,
			"MaxTargets must be positive and fit a target index"
		);
		assert!(
			T::MaxWinnersPerPage::get() > 0,
			"MaxWinnersPerPage must be positive"
		);
		assert!(
			T::MaxBackersPerWinner::get() >= page,
			"MaxBackersPerWinner must hold a full voter page"
		);
		assert!(
			T::MaxBackersPerWinnerFinal::get() >= pages.saturating_mul(page),
			"MaxBackersPerWinnerFinal must hold every voter"
		);
		let usable = Self::budget().saturating_sub(Self::block_overhead());
		assert!(
			Self::snapshot_step().all_lte(usable) && Self::round_step().all_lt(usable),
			"RoundBudget must fit the heaviest step"
		);
		assert!(
			Self::export_weight().all_lte(T::BlockWeights::get().max_block),
			"a page export must fit a block"
		);
	}
}
