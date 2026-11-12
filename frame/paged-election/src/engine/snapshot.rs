// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The snapshot: targets and seats in one step, then one voter page per step,
//! most significant first, as staking pages its voters.

use crate::{
	Candidate, Candidates, Config, CurrentPhase, Event, FailReason, Meta, PageInfo, PageInfos,
	Pallet, Phase, SnapshotVoter, TargetIndex, Targets, VoterOf, VoterPages, WeightInfo,
};
use alloc::{
	collections::{BTreeMap, BTreeSet},
	vec,
	vec::Vec,
};
use frame_election_provider_support::{
	ElectionDataProvider, PageIndex,
	bounds::{CountBound, DataProviderBounds},
};
use frame_support::{BoundedVec, traits::Get, weights::WeightMeter};

impl<T: Config> Pallet<T> {
	/// Takes the targets and the seats. Priced in full whatever staking returns:
	/// it may read more candidates than it keeps.
	pub(crate) fn snapshot_targets(meter: &mut WeightMeter) -> Option<Phase> {
		let cost = T::WeightInfo::snapshot_targets(T::MaxTargets::get());
		if !meter.can_consume(cost) {
			return None;
		}
		let next = match Self::take_targets() {
			Ok(()) => Phase::Voters(Self::msp()),
			Err(reason) => Self::fail(reason),
		};
		CurrentPhase::<T>::put(next);
		meter.consume(cost);
		Some(next)
	}

	/// Stores the targets, deduplicated, and the seats.
	fn take_targets() -> Result<(), FailReason> {
		let bounds = DataProviderBounds {
			count: Some(CountBound(T::MaxTargets::get())),
			size: None,
		};
		// Staking's target snapshot is single-paged.
		let mut targets =
			T::DataProvider::electable_targets(bounds, 0).map_err(|_| FailReason::DataProvider)?;
		let desired = T::DataProvider::desired_targets().map_err(|_| FailReason::DataProvider)?;
		if desired > T::MaxWinnersPerPage::get() {
			return Err(FailReason::TooManySeats);
		}
		let mut seen = BTreeSet::new();
		targets.retain(|t| seen.insert(t.clone()));
		let targets: BoundedVec<_, T::MaxTargets> =
			targets.try_into().map_err(|_| FailReason::DataProvider)?;
		let count = targets.len() as u32;

		Candidates::<T>::put(BoundedVec::truncate_from(vec![
			Candidate::default();
			targets.len()
		]));
		Targets::<T>::put(targets);
		Meta::<T>::mutate(|meta| {
			let meta = meta.get_or_insert_with(Default::default);
			meta.targets = count;
			meta.desired = desired;
			meta.to_elect = desired.min(count);
		});
		Ok(())
	}

	/// Takes voter `page`. Priced in full whatever staking returns: it walks
	/// past voters without stake, up to twice the page.
	pub(crate) fn snapshot_voters(page: PageIndex, meter: &mut WeightMeter) -> Option<Phase> {
		let limit = T::VoterSnapshotPerBlock::get();
		let cost = T::WeightInfo::snapshot_voters(limit);
		if !meter.can_consume(cost) {
			return None;
		}
		let bounds = DataProviderBounds {
			count: Some(CountBound(limit)),
			size: None,
		};
		let next = match T::DataProvider::electing_voters(bounds, page)
			.map_err(|_| FailReason::DataProvider)
			.and_then(|voters| Self::store_page(page, voters))
		{
			Ok(()) if page == 0 => Self::snapshot_taken(),
			Ok(()) => Phase::Voters(page - 1),
			Err(reason) => Self::fail(reason),
		};
		CurrentPhase::<T>::put(next);
		meter.consume(cost);
		Some(next)
	}

	/// Maps a page's votes to candidate indices, keeps the voters that count
	/// and adds their stake to the candidates' approval. More voters than a
	/// page holds is staking's fault, not to be cut silently.
	fn store_page(
		page: PageIndex,
		voters: Vec<frame_election_provider_support::VoterOf<T::DataProvider>>,
	) -> Result<(), FailReason> {
		let limit = T::VoterSnapshotPerBlock::get() as usize;
		if voters.len() > limit {
			log::error!(target: crate::LOG_TARGET, "page {page}: {} voters over {limit}", voters.len());
			return Err(FailReason::DataProvider);
		}
		let targets = Targets::<T>::get();
		let index: BTreeMap<&T::AccountId, TargetIndex> = targets
			.iter()
			.enumerate()
			.filter_map(|(i, t)| Some((t, TargetIndex::try_from(i).ok()?)))
			.collect();
		let mut candidates = Candidates::<T>::get();
		let mut approvers = vec![0u32; targets.len()];
		let mut stored: Vec<VoterOf<T>> = Vec::with_capacity(voters.len());
		let mut edges = 0u32;
		for (who, stake, votes) in voters {
			if stake == 0 {
				continue;
			}
			let mut valid = BoundedVec::new();
			for target in votes.iter() {
				if let Some(&i) = index.get(target)
					&& !valid.contains(&i)
					&& valid.try_push(i).is_err()
				{
					return Err(FailReason::Inconsistent);
				}
			}
			if valid.is_empty() {
				continue;
			}
			for &i in valid.iter() {
				let (Some(candidate), Some(count)) = (
					candidates.get_mut(usize::from(i)),
					approvers.get_mut(usize::from(i)),
				) else {
					return Err(FailReason::Inconsistent);
				};
				candidate.approval = candidate.approval.saturating_add(stake.into());
				*count = count.saturating_add(1);
			}
			edges = edges.saturating_add(valid.len() as u32);
			stored.push(SnapshotVoter {
				who,
				stake,
				votes: valid,
			});
		}

		let count = stored.len() as u32;
		if count > 0 {
			VoterPages::<T>::insert(page, BoundedVec::truncate_from(stored));
			PageInfos::<T>::insert(
				page,
				PageInfo {
					voters: count,
					approvers: BoundedVec::truncate_from(approvers),
				},
			);
		}
		Candidates::<T>::put(candidates);
		Meta::<T>::mutate(|meta| {
			if let Some(meta) = meta {
				meta.pages = meta.pages.saturating_add(u32::from(count > 0));
				meta.voters = meta.voters.saturating_add(count);
				meta.edges = meta.edges.saturating_add(edges);
			}
		});
		Ok(())
	}

	fn snapshot_taken() -> Phase {
		let meta = Meta::<T>::get().unwrap_or_default();
		Self::deposit_event(Event::SnapshotTaken {
			targets: meta.targets,
			voters: meta.voters,
			edges: meta.edges,
			pages: meta.pages,
			to_elect: meta.to_elect,
		});
		Phase::Select
	}
}
