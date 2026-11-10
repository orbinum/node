//! Keeping the voter list's walk to accounts that vote.
//!
//! Staking walks the voter list for each snapshot page and counts every node it
//! visits, voter or not, against twice the page. If a page takes no voter, its
//! cursor stays put, so a long enough run of non-voters empties every page
//! after it. Non-voters reach the list two ways:
//!
//! - removals while the snapshot holds the list locked: `chill`, a full
//!   `unbond`, `deregister_validator` and the like remove the nominator or the
//!   candidate, but the list refuses to drop the node until the snapshot ends;
//! - `staking.kick`, which can leave a nomination with no targets for good.
//!
//! [`LiveVoters`] hides non-voters from staking's walk, up to a page of them per
//! walk, with their reads registered; [`KickKeepsNominations`] stops `kick`
//! from emptying a nomination. A run longer than the skip budget still reaches
//! staking's count: it needs that many removals in the snapshot's few blocks.

use crate::{
	staking::{params::VOTER_SNAPSHOT_PER_BLOCK, register_reads},
	AccountId, Runtime, RuntimeCall, Staking,
};
use alloc::boxed::Box;
use core::marker::PhantomData;
use frame_election_provider_support::SortedListProvider;
use frame_support::traits::Contains;
use sp_runtime::traits::StaticLookup;
use sp_staking::StakingInterface;

/// Non-voters one walk hides before letting the rest through.
pub const MAX_SKIPPED_VOTERS: u32 = VOTER_SNAPSHOT_PER_BLOCK;

/// Reads to look at a node and skip it: the node, the candidacy, the
/// nomination, the bonded controller and the ledger.
const READS_PER_SKIPPED_VOTER: u64 = 5;

/// Whether `who` would vote in a snapshot: a candidate or a nominator with
/// targets, with stake.
pub fn votes(who: &AccountId) -> bool {
	let nominates = || {
		pallet_staking_async::Nominators::<Runtime>::get(who)
			.is_some_and(|nominations| !nominations.targets.is_empty())
	};
	(pallet_staking_async::Validators::<Runtime>::contains_key(who) || nominates())
		&& <Staking as StakingInterface>::stake(who).is_ok_and(|stake| stake.active > 0)
}

fn live(inner: Box<dyn Iterator<Item = AccountId>>) -> Box<dyn Iterator<Item = AccountId>> {
	let mut skipped = 0u32;
	Box::new(inner.filter(move |who| {
		if skipped >= MAX_SKIPPED_VOTERS || votes(who) {
			return true;
		}
		skipped += 1;
		register_reads(READS_PER_SKIPPED_VOTER);
		false
	}))
}

/// `pallet_staking_async::Config::VoterList`: `Inner`, with non-voters hidden
/// from iteration (see the module docs). Everything else passes through, so
/// `Inner` stays consistent with staking's maps.
pub struct LiveVoters<Inner>(PhantomData<Inner>);

impl<Inner> SortedListProvider<AccountId> for LiveVoters<Inner>
where
	Inner: SortedListProvider<AccountId>,
{
	type Error = Inner::Error;
	type Score = Inner::Score;

	fn range() -> (Self::Score, Self::Score) {
		Inner::range()
	}
	fn iter() -> Box<dyn Iterator<Item = AccountId>> {
		live(Inner::iter())
	}
	fn lock() {
		Inner::lock()
	}
	fn unlock() {
		Inner::unlock()
	}
	fn iter_from(start: &AccountId) -> Result<Box<dyn Iterator<Item = AccountId>>, Self::Error> {
		Inner::iter_from(start).map(live)
	}
	fn count() -> u32 {
		Inner::count()
	}
	fn contains(id: &AccountId) -> bool {
		Inner::contains(id)
	}
	fn on_insert(id: AccountId, score: Self::Score) -> Result<(), Self::Error> {
		Inner::on_insert(id, score)
	}
	fn on_update(id: &AccountId, score: Self::Score) -> Result<(), Self::Error> {
		Inner::on_update(id, score)
	}
	fn get_score(id: &AccountId) -> Result<Self::Score, Self::Error> {
		Inner::get_score(id)
	}
	fn on_increase(id: &AccountId, additional: Self::Score) -> Result<(), Self::Error> {
		Inner::on_increase(id, additional)
	}
	fn on_decrease(id: &AccountId, decreased: Self::Score) -> Result<(), Self::Error> {
		Inner::on_decrease(id, decreased)
	}
	fn on_remove(id: &AccountId) -> Result<(), Self::Error> {
		Inner::on_remove(id)
	}
	fn unsafe_regenerate(
		all: impl IntoIterator<Item = AccountId>,
		score_of: Box<dyn Fn(&AccountId) -> Option<Self::Score>>,
	) -> u32 {
		Inner::unsafe_regenerate(all, score_of)
	}
	fn unsafe_clear() {
		Inner::unsafe_clear()
	}
	#[cfg(feature = "try-runtime")]
	fn try_state() -> Result<(), sp_runtime::TryRuntimeError> {
		Inner::try_state()
	}
	#[cfg(feature = "runtime-benchmarks")]
	fn score_update_worst_case(who: &AccountId, is_increase: bool) -> Self::Score {
		Inner::score_update_worst_case(who, is_increase)
	}
}

/// Part of `frame_system::Config::BaseCallFilter`: a `staking.kick` that names
/// a nominator with one target or none is refused. Kicking the only target
/// would leave the nomination empty, a non-voter staking keeps in the voter
/// list; if the target is someone else's, the kick would do nothing for it.
pub struct KickKeepsNominations;

impl Contains<RuntimeCall> for KickKeepsNominations {
	fn contains(call: &RuntimeCall) -> bool {
		let RuntimeCall::Staking(pallet_staking_async::Call::kick { who }) = call else {
			return true;
		};
		who.iter().all(|nominator| {
			// An unknown address fails the call itself.
			<Runtime as frame_system::Config>::Lookup::lookup(nominator.clone()).map_or(
				true,
				|nominator| {
					pallet_staking_async::Nominators::<Runtime>::get(&nominator)
						.is_none_or(|nominations| nominations.targets.len() > 1)
				},
			)
		})
	}
}
