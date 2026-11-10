//! What must hold after every block: checked by `try_state` and by the tests.

use crate::{
	Candidates, Config, CurrentPhase, Meta, PageInfos, Pallet, Phase, Targets, VoterPages, Winners,
	phragmen,
};
use alloc::{collections::BTreeSet, vec};
use frame_election_provider_support::ExtendedBalance;
use frame_support::{ensure, traits::Get};
use sp_runtime::TryRuntimeError;

impl<T: Config> Pallet<T> {
	pub(crate) fn do_try_state() -> Result<(), TryRuntimeError> {
		let phase = CurrentPhase::<T>::get();
		let targets = Targets::<T>::get();
		let candidates = Candidates::<T>::get();
		let winners = Winners::<T>::get();
		let stored = VoterPages::<T>::iter_keys().count();

		let Some(meta) = Meta::<T>::get() else {
			ensure!(phase == Phase::Off, "a running election has bookkeeping");
			ensure!(
				targets.is_empty() && candidates.is_empty() && winners.is_empty(),
				"no election leaves no snapshot"
			);
			ensure!(
				stored == 0 && PageInfos::<T>::iter_keys().next().is_none(),
				"no election leaves no voter pages"
			);
			return Ok(());
		};
		ensure!(phase != Phase::Off, "an idle election has no bookkeeping");
		if phase == Phase::Targets {
			ensure!(
				targets.is_empty() && stored == 0,
				"nothing is taken before the targets"
			);
			return Ok(());
		}

		// Snapshot.
		ensure!(
			candidates.len() == targets.len(),
			"one score sum per target"
		);
		ensure!(meta.targets as usize == targets.len(), "target count");
		ensure!(
			targets.iter().collect::<BTreeSet<_>>().len() == targets.len(),
			"targets are unique"
		);
		ensure!(
			meta.to_elect == meta.desired.min(meta.targets),
			"winners to elect"
		);
		ensure!(
			meta.desired <= T::MaxWinnersPerPage::get(),
			"seats within bounds"
		);
		let mut approval = vec![ExtendedBalance::default(); targets.len()];
		let (mut voters, mut edges) = (0u32, 0u32);
		for (page, list) in VoterPages::<T>::iter() {
			ensure!(page < T::Pages::get(), "voter page within the pages");
			if let Phase::Voters(next) = phase {
				ensure!(page > next, "only taken pages are stored");
			}
			let info = PageInfos::<T>::get(page).ok_or("every voter page has its info")?;
			ensure!(
				info.voters as usize == list.len() && !list.is_empty(),
				"page voters"
			);
			let mut approvers = vec![0u32; targets.len()];
			for voter in list.iter() {
				ensure!(
					voter.stake > 0 && !voter.votes.is_empty(),
					"stored voters count"
				);
				ensure!(
					voter.votes.iter().collect::<BTreeSet<_>>().len() == voter.votes.len(),
					"votes are unique"
				);
				for &t in voter.votes.iter() {
					let slot = approval
						.get_mut(usize::from(t))
						.ok_or("vote within the targets")?;
					*slot = slot.saturating_add(voter.stake.into());
					if let Some(count) = approvers.get_mut(usize::from(t)) {
						*count += 1;
					}
				}
				edges += voter.votes.len() as u32;
			}
			ensure!(info.approvers.to_vec() == approvers, "page approvers");
			voters += list.len() as u32;
		}
		ensure!(
			PageInfos::<T>::iter_keys().count() == stored,
			"one info per voter page"
		);
		ensure!(meta.pages as usize == stored, "page count");
		ensure!(
			meta.voters == voters && meta.edges == edges,
			"voter and edge counts"
		);
		ensure!(
			candidates
				.iter()
				.map(|c| c.approval)
				.eq(approval.iter().copied()),
			"approval is the stake of the approving voters"
		);

		// Winners.
		ensure!(
			winners.len() as u32 <= meta.to_elect,
			"no more winners than seats"
		);
		ensure!(
			winners.iter().map(|w| w.0).collect::<BTreeSet<_>>().len() == winners.len(),
			"winners are unique"
		);
		ensure!(
			winners.iter().all(|w| usize::from(w.0) < targets.len()),
			"winners are targets"
		);
		match phase {
			Phase::Voters(page) => {
				ensure!(page < T::Pages::get(), "voter page within the pages");
				ensure!(winners.is_empty(), "no winner before the snapshot ends");
			}
			// With no seats, `Select` only reports the election done.
			Phase::Select => ensure!(
				(winners.len() as u32) < meta.to_elect || meta.to_elect == 0,
				"selecting only while seats remain"
			),
			Phase::Apply { page, winner } => {
				ensure!(page < T::Pages::get(), "applied page within the pages");
				ensure!(
					winners.last().map(|w| w.0) == Some(winner),
					"applying the last winner"
				);
				ensure!(
					(winners.len() as u32) < meta.to_elect,
					"no pass after the last winner"
				);
			}
			Phase::Done => ensure!(winners.len() as u32 == meta.to_elect, "every seat filled"),
			_ => {}
		}

		// Score sums of unelected candidates match the applied loads.
		let applying = match phase {
			Phase::Select => None,
			Phase::Apply { page, .. } => Some(page),
			_ => return Ok(()),
		};
		let latest = winners.len().saturating_sub(1) as u32;
		let rounds = Self::rounds_of(targets.len(), &winners);
		let mut sums = vec![phragmen::Accumulator::default(); targets.len()];
		for (page, list) in VoterPages::<T>::iter() {
			// The last winner is applied to every page in `Select`, and to the
			// pages above the current one in `Apply`.
			let applied = applying.is_none_or(|current| page > current);
			for voter in list.iter() {
				let load = voter
					.votes
					.iter()
					.filter_map(|&t| rounds.get(usize::from(t)).copied().flatten())
					.filter(|&r| applied || r < latest)
					.max()
					.and_then(|r| winners.get(r as usize))
					.map_or(0, |w| w.1);
				for &t in voter.votes.iter() {
					let (Some(None), Some(sum), Some(approval)) = (
						rounds.get(usize::from(t)),
						sums.get_mut(usize::from(t)),
						approval.get(usize::from(t)),
					) else {
						continue;
					};
					sum.add(phragmen::contribution(load, voter.stake.into(), *approval))
						.ok_or("score sum overflow")?;
				}
			}
		}
		for (i, candidate) in candidates.iter().enumerate() {
			if rounds.get(i).copied().flatten().is_none() {
				ensure!(
					Some(&candidate.sum) == sums.get(i),
					"score sums match the loads"
				);
			}
		}
		Ok(())
	}
}
