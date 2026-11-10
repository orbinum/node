//! A page's supports, rebuilt from the winners' scores: each voter's stake is
//! split across the winners it approves as upstream's backing step does.

use crate::{
	Config, Event, FailReason, PageInfos, Pallet, Targets, VoterPages, Winners, phragmen,
	types::ElectionError,
};
use alloc::{vec, vec::Vec};
use frame_election_provider_support::{
	BoundedSupport, BoundedSupports, BoundedSupportsOf, ExtendedBalance, PageIndex,
};
use frame_support::BoundedVec;

type Backing<AccountId> = (ExtendedBalance, Vec<(AccountId, ExtendedBalance)>);

impl<T: Config> Pallet<T> {
	/// The supports of voter `page`, winners in election order. A page that was
	/// stored but cannot be read errors instead of exporting as empty.
	pub(crate) fn export(page: PageIndex) -> Result<BoundedSupportsOf<Self>, ElectionError> {
		let voters = match VoterPages::<T>::get(page) {
			Some(voters) => voters.into_inner(),
			None if PageInfos::<T>::contains_key(page) || VoterPages::<T>::contains_key(page) => {
				log::error!(target: crate::LOG_TARGET, "voter page {page} is missing or undecodable");
				return Err(ElectionError::Failed(FailReason::Inconsistent));
			}
			None => Vec::new(),
		};
		let targets = Targets::<T>::get();
		let winners = Winners::<T>::get();
		let rounds = Self::rounds_of(targets.len(), &winners);
		let score = |round: u32| winners.get(round as usize).map_or(0, |&(_, s)| s);

		// Per winner, in election order: total and backers.
		let mut supports: Vec<Backing<T::AccountId>> = vec![(0, Vec::new()); winners.len()];
		let mut backers = 0u32;
		for voter in voters {
			let approved: Vec<(u16, u32)> = voter
				.votes
				.iter()
				.filter_map(|&t| Some((t, rounds.get(usize::from(t)).copied().flatten()?)))
				.collect();
			if approved.is_empty() {
				continue;
			}
			let weights = phragmen::distribute(voter.stake, &approved, score);
			backers = backers.saturating_add(u32::from(!weights.is_empty()));
			for (target, weight) in weights {
				let round = rounds.get(usize::from(target)).copied().flatten();
				let Some((total, voters)) = round.and_then(|r| supports.get_mut(r as usize)) else {
					continue;
				};
				*total = total.saturating_add(weight);
				voters.push((voter.who.clone(), weight));
			}
		}

		let mut out = BoundedVec::new();
		for ((target, _), (total, voters)) in winners.iter().zip(supports) {
			if voters.is_empty() {
				continue;
			}
			let who = targets
				.get(usize::from(*target))
				.ok_or(ElectionError::BoundsExceeded)?;
			let voters = BoundedVec::try_from(voters).map_err(|_| ElectionError::BoundsExceeded)?;
			out.try_push((who.clone(), BoundedSupport { total, voters }))
				.map_err(|_| ElectionError::BoundsExceeded)?;
		}

		Self::deposit_event(Event::PageExported {
			page,
			winners: out.len() as u32,
			backers,
		});
		Ok(BoundedSupports(out))
	}
}
