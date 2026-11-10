//! The rounds: elect the lowest score, then pass over the voter pages giving
//! the winner's score as load to the voters approving it, which updates the
//! sums of the candidates they also approve.

use crate::{
	Candidates, Config, CurrentPhase, Event, FailReason, Meta, PageInfos, Pallet, Phase,
	TargetIndex, VoterPages, WeightInfo, Winners,
	phragmen::{self, Rank},
};
use alloc::{vec, vec::Vec};
use frame_election_provider_support::{ExtendedBalance, PageIndex};
use frame_support::{traits::Get, weights::WeightMeter};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::Saturating;

impl<T: Config> Pallet<T> {
	/// Each target's election round, if elected, from the winners list.
	pub(crate) fn rounds_of(
		targets: usize,
		winners: &[(TargetIndex, ExtendedBalance)],
	) -> Vec<Option<u32>> {
		let mut rounds = vec![None; targets];
		for (round, &(target, _)) in winners.iter().enumerate() {
			if let Some(slot) = rounds.get_mut(usize::from(target)) {
				*slot = Some(round as u32);
			}
		}
		rounds
	}

	/// Elects the unelected candidate with the lowest score, the first on ties.
	pub(crate) fn select(now: BlockNumberFor<T>, meter: &mut WeightMeter) -> Option<Phase> {
		if !meter.can_consume(T::WeightInfo::select_winner(T::MaxTargets::get())) {
			return None;
		}
		let candidates = Candidates::<T>::get();
		let next = Self::elect_next(now, &candidates);
		CurrentPhase::<T>::put(next);
		meter.consume(T::WeightInfo::select_winner(candidates.len() as u32));
		Some(next)
	}

	fn elect_next(now: BlockNumberFor<T>, candidates: &[crate::Candidate]) -> Phase {
		let Some(mut meta) = Meta::<T>::get() else {
			return Self::fail(FailReason::Inconsistent);
		};
		let mut winners = Winners::<T>::get();
		let rounds = Self::rounds_of(candidates.len(), &winners);

		let mut best: Option<(usize, Rank)> = None;
		let mut saturated = false;
		for (i, candidate) in candidates.iter().enumerate() {
			if rounds.get(i).copied().flatten().is_some() {
				continue;
			}
			let (rank, saturates) = phragmen::rank(candidate.approval, &candidate.sum);
			saturated |= saturates;
			if best.is_none_or(|(_, b)| rank < b) {
				best = Some((i, rank));
			}
		}

		let round = winners.len() as u32;
		if saturated && !meta.saturated {
			meta.saturated = true;
			Meta::<T>::put(meta);
			Self::deposit_event(Event::ScoreSaturated { round });
		}
		if round < meta.to_elect {
			let Some((i, rank)) = best else {
				return Self::fail(FailReason::Inconsistent);
			};
			let score = match rank {
				Rank::Scored(score) => score,
				Rank::Unapproved => ExtendedBalance::MAX,
			};
			let Ok(winner) = TargetIndex::try_from(i) else {
				return Self::fail(FailReason::Inconsistent);
			};
			if winners.try_push((winner, score)).is_err() {
				return Self::fail(FailReason::Inconsistent);
			}
			Winners::<T>::put(&winners);
			if (winners.len() as u32) < meta.to_elect {
				return Phase::Apply {
					page: Self::msp(),
					winner,
				};
			}
		}

		Self::deposit_event(Event::ElectionDone {
			winners: winners.len() as u32,
			blocks: now.saturating_sub(meta.started).saturating_add(1u32.into()),
		});
		Phase::Done
	}

	/// Applies the last winner's score to the voters of `page` approving it.
	pub(crate) fn apply(
		page: PageIndex,
		winner: TargetIndex,
		meter: &mut WeightMeter,
	) -> Option<Phase> {
		let peek = Self::db().reads(1);
		if !meter.can_consume(peek) {
			return None;
		}
		let (scanned, approving) = PageInfos::<T>::get(page)
			.map(|info| {
				let approving = info.approvers_of(winner);
				(info.voters.saturating_sub(approving), approving)
			})
			.unwrap_or_default();
		let cost = if approving == 0 {
			Self::skip_weight()
		} else {
			T::WeightInfo::apply_page(scanned, approving)
		};
		if !meter.can_consume(cost) {
			meter.consume(peek);
			return None;
		}

		let next = if approving > 0 && Self::apply_page(page, winner).is_none() {
			Self::fail(FailReason::Inconsistent)
		} else if page == 0 {
			Phase::Select
		} else {
			Phase::Apply {
				page: page - 1,
				winner,
			}
		};
		CurrentPhase::<T>::put(next);
		meter.consume(cost);
		Some(next)
	}

	/// For each voter of `page` approving `winner`, the latest winner, moves
	/// its contribution to the unelected candidates it approves from its old
	/// load (the score of its previous winner) to the winner's score.
	fn apply_page(page: PageIndex, winner: TargetIndex) -> Option<()> {
		let voters = VoterPages::<T>::get(page)?;
		let mut candidates = Candidates::<T>::get();
		let winners = Winners::<T>::get();
		let &(last, new_load) = winners.last()?;
		if last != winner {
			return None;
		}
		let latest = winners.len().saturating_sub(1) as u32;
		let rounds = Self::rounds_of(candidates.len(), &winners);
		let round_of = |t: &TargetIndex| rounds.get(usize::from(*t)).copied().flatten();

		for voter in voters.iter().filter(|v| v.votes.contains(&winner)) {
			let stake = ExtendedBalance::from(voter.stake);
			let old_load = voter
				.votes
				.iter()
				.filter_map(round_of)
				.filter(|&r| r < latest)
				.max()
				.and_then(|r| winners.get(r as usize))
				.map_or(0, |&(_, score)| score);
			for target in voter.votes.iter().filter(|t| round_of(t).is_none()) {
				let candidate = candidates.get_mut(usize::from(*target))?;
				if candidate.approval == 0 {
					continue;
				}
				if old_load > 0 {
					candidate.sum.sub(phragmen::contribution(
						old_load,
						stake,
						candidate.approval,
					))?;
				}
				candidate
					.sum
					.add(phragmen::contribution(new_load, stake, candidate.approval))?;
			}
		}
		Candidates::<T>::put(candidates);
		Some(())
	}
}
