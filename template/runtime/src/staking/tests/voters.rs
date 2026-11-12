// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The voter list's walk: accounts that stopped voting while the snapshot held
//! the list locked, or whose nomination `kick` would empty, never cost the
//! voters behind them their page.

use super::{bond, offer};
use crate::{
	staking::{
		live::{LiveVoters, MAX_SKIPPED_VOTERS},
		params::TEST_MIN_NOMINATOR_BOND,
	},
	test_utils::with_ext,
	AccountId, Runtime, RuntimeCall, RuntimeOrigin, Staking, VoterList,
};
use frame_election_provider_support::{
	bounds::{CountBound, DataProviderBounds},
	ElectionDataProvider, SortedListProvider,
};
use frame_support::{assert_noop, assert_ok, dispatch::DispatchClass, weights::Weight};
use pallet_bags_list::{Instance1, ListNodes};
use sp_runtime::{traits::Dispatchable, DispatchError};
use sp_staking::StakingInterface;

fn nth(i: u32) -> AccountId {
	let mut raw = [0x5a; 32];
	raw[..4].copy_from_slice(&i.to_le_bytes());
	AccountId::from(raw)
}

fn nominator(who: &AccountId, stake: u128, targets: Vec<AccountId>) {
	bond(who, stake);
	assert_ok!(<Staking as StakingInterface>::nominate(who, targets));
}

fn one_voter(page: u32) -> Vec<AccountId> {
	let bounds = DataProviderBounds {
		count: Some(CountBound(1)),
		size: None,
	};
	<Staking as ElectionDataProvider>::electing_voters(bounds, page)
		.unwrap()
		.into_iter()
		.map(|(who, _, _)| who)
		.collect()
}

fn mandatory_weight() -> Weight {
	*frame_system::Pallet::<Runtime>::block_weight().get(DispatchClass::Mandatory)
}

/// Nominators chilled after the snapshot took its first page stay in the locked
/// list. Staking alone would count them against the next page (twice its size,
/// here 2) and return it empty, leaving everyone below out of the election.
#[test]
fn voters_chilled_mid_snapshot_do_not_empty_the_next_page() {
	with_ext(|| {
		let validator = nth(0);
		bond(&validator, 1_000 * TEST_MIN_NOMINATOR_BOND);
		offer(&validator);
		let (top, honest) = (nth(1), nth(2));
		nominator(&top, 100 * TEST_MIN_NOMINATOR_BOND, vec![validator.clone()]);
		let chilled: Vec<_> = (10..20).map(nth).collect();
		for who in &chilled {
			nominator(who, 10 * TEST_MIN_NOMINATOR_BOND, vec![validator.clone()]);
		}
		nominator(&honest, TEST_MIN_NOMINATOR_BOND, vec![validator.clone()]);

		assert_eq!(one_voter(1), vec![top]);
		for who in &chilled {
			assert_ok!(<Staking as StakingInterface>::chill(who));
			assert!(ListNodes::<Runtime, Instance1>::contains_key(who));
		}
		let before = mandatory_weight();
		assert_eq!(one_voter(0), vec![honest]);
		let reads = <Runtime as frame_system::Config>::DbWeight::get().reads(5 * 10);
		assert_eq!(mandatory_weight(), before + reads);
	});
}

/// A walk hides at most `MAX_SKIPPED_VOTERS` non-voters; past that it lets
/// them through, so its cost stays bounded.
#[test]
fn the_skip_budget_bounds_a_walk() {
	with_ext(|| {
		let validator = nth(0);
		bond(&validator, 1_000 * TEST_MIN_NOMINATOR_BOND);
		offer(&validator);
		let stale = MAX_SKIPPED_VOTERS + 2;
		for i in 0..stale {
			assert_ok!(<VoterList as SortedListProvider<AccountId>>::on_insert(
				nth(10 + i),
				u64::MAX / 2
			));
		}
		let voter = nth(1);
		nominator(&voter, TEST_MIN_NOMINATOR_BOND, vec![validator]);

		let before = mandatory_weight();
		let walked: Vec<_> = LiveVoters::<VoterList>::iter().collect();
		assert_eq!(
			walked,
			vec![
				nth(10 + MAX_SKIPPED_VOTERS),
				nth(11 + MAX_SKIPPED_VOTERS),
				voter
			]
		);
		let reads = <Runtime as frame_system::Config>::DbWeight::get()
			.reads(5 * u64::from(MAX_SKIPPED_VOTERS));
		assert_eq!(mandatory_weight(), before + reads);
	});
}

/// Validators, nominators with targets and stake are voters; a nomination
/// without targets or a ledger without stake is not.
#[test]
fn votes_needs_a_candidacy_or_targets_and_stake() {
	use crate::staking::live::votes;
	with_ext(|| {
		let (validator, nominating, idle) = (nth(0), nth(1), nth(2));
		bond(&validator, 1_000 * TEST_MIN_NOMINATOR_BOND);
		offer(&validator);
		nominator(
			&nominating,
			TEST_MIN_NOMINATOR_BOND,
			vec![validator.clone()],
		);
		bond(&idle, TEST_MIN_NOMINATOR_BOND);
		assert!(votes(&validator) && votes(&nominating));
		assert!(!votes(&idle) && !votes(&nth(3)));

		pallet_staking_async::Nominators::<Runtime>::mutate(&nominating, |n| {
			n.as_mut().unwrap().targets = Default::default()
		});
		assert!(!votes(&nominating));
	});
}

fn kick(
	by: &AccountId,
	who: &AccountId,
) -> sp_runtime::DispatchResultWithInfo<frame_support::dispatch::PostDispatchInfo> {
	RuntimeCall::Staking(pallet_staking_async::Call::kick {
		who: vec![who.clone()],
	})
	.dispatch(RuntimeOrigin::signed(by.clone()))
}

/// Kicking a nominator's only target would leave a nomination without targets
/// in the voter list for good; with another target the kick goes through.
#[test]
fn kick_cannot_empty_a_nomination() {
	with_ext(|| {
		let (validator, other) = (nth(0), nth(1));
		for v in [&validator, &other] {
			bond(v, 1_000 * TEST_MIN_NOMINATOR_BOND);
			offer(v);
		}
		let (only, both) = (nth(2), nth(3));
		nominator(&only, TEST_MIN_NOMINATOR_BOND, vec![validator.clone()]);
		nominator(
			&both,
			TEST_MIN_NOMINATOR_BOND,
			vec![validator.clone(), other.clone()],
		);

		assert_noop!(
			kick(&validator, &only).map_err(|e| e.error),
			DispatchError::from(frame_system::Error::<Runtime>::CallFiltered)
		);
		assert_ok!(kick(&validator, &both));
		let targets = pallet_staking_async::Nominators::<Runtime>::get(&both)
			.unwrap()
			.targets
			.into_inner();
		assert_eq!(targets, vec![other]);
	});
}
