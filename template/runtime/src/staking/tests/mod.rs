//! Staking as the runtime wires it, one module per concern.
//!
//! - `bonds`: the direct bond's lifecycle and its hold.
//! - `genesis`: what each preset bonds and caps.
//! - `admission`: the admission rule, its enforcement points and the candidacy
//!   extension.
//! - `commission`: the commission ceiling and its clamp.
//! - `election`: each era's on-chain election and the hand-over of its set.
//! - `offences`: a GRANDPA equivocation, from report to slash.
//! - `pools`: nomination pools through delegated staking.
//! - `auto_payout`: era rewards paid without transactions.
//! - `emission`: era rewards against the schedule over a year, and their split.
//! - `pruning`: eras past the history pruned from `on_idle`.
//! - `local_relay`: the direct calls between the two staking clients.
//! - `voters`: the voter list's walk kept to accounts that vote.

mod admission;
mod auto_payout;
mod bonds;
mod commission;
mod election;
mod emission;
mod genesis;
mod local_relay;
mod offences;
mod pools;
mod pruning;
mod unbonding;
mod voters;

use crate::{
	staking::admission::AdmissionFilteredTargets, test_utils::with_ext, AccountId, Balance,
	Balances, Runtime, RuntimeOrigin, Staking,
};
use frame_election_provider_support::SortedListProvider;
use frame_support::{
	assert_ok,
	traits::{fungible::Mutate, Get},
};
use pallet_staking_async::{UseValidatorsMap, ValidatorPrefs};
use sp_staking::StakingInterface;

type Targets = AdmissionFilteredTargets<UseValidatorsMap<Runtime>>;

/// Turns nominator slashing back on, as governance may (`set_staking_configs`), from
/// the active era: the tests of what a slash does to nominators and pools.
pub(super) fn nominators_slashable() {
	pallet_staking_async::AreNominatorsSlashable::<crate::Runtime>::put(true);
	let era = pallet_staking_async::ActiveEra::<crate::Runtime>::get().map_or(0, |era| era.index);
	pallet_staking_async::ErasNominatorsSlashable::<crate::Runtime>::insert(era, true);
}

pub(super) fn account(n: u8) -> AccountId {
	AccountId::from([n; 32])
}

pub(super) fn set_keys(who: &AccountId) {
	let raw: [u8; 32] = who.clone().into();
	pallet_session::NextKeys::<Runtime>::insert(
		who,
		crate::opaque::SessionKeys {
			aura: sp_core::sr25519::Public::from_raw(raw).into(),
			grandpa: sp_core::ed25519::Public::from_raw(raw).into(),
		},
	);
}

pub(super) fn bond(who: &AccountId, value: Balance) {
	Balances::set_balance(who, value * 2);
	assert_ok!(<Staking as StakingInterface>::bond(who, value, who));
}

/// Offers `who` as a validator the way root's `sudo_as` would: no extension.
pub(super) fn offer(who: &AccountId) {
	pallet_staking_async::Validators::<Runtime>::insert(who, ValidatorPrefs::default());
}

pub(super) fn approve(who: &AccountId) {
	pallet_validator_set::ApprovedValidators::<Runtime>::mutate(|v| {
		v.try_push(who.clone()).unwrap()
	});
}

pub(super) fn elected_candidates() -> Vec<AccountId> {
	Targets::iter().collect()
}

/// With a zero existential deposit, unbonding everything and withdrawing removes the
/// ledger.
#[test]
fn full_unbond_and_withdraw_leaves_no_ledger() {
	with_ext(|| {
		let at_era = |index| {
			pallet_staking_async::ActiveEra::<Runtime>::put(pallet_staking_async::ActiveEraInfo {
				index,
				start: None,
			});
			pallet_staking_async::CurrentEra::<Runtime>::put(index);
		};
		at_era(0);
		let who = account(1);
		bond(&who, 1_000);
		assert_ok!(<Staking as StakingInterface>::unbond(&who, 1_000));
		at_era(crate::staking::params::BONDING_DURATION + 1);
		assert_ok!(Staking::withdraw_unbonded(
			RuntimeOrigin::signed(who.clone()),
			0
		));
		assert!(<Staking as StakingInterface>::stake(&who).is_err());
	});
}

#[test]
fn era_payout_reads_the_active_era() {
	with_ext(|| {
		pallet_staking_async::ActiveEra::<Runtime>::put(pallet_staking_async::ActiveEraInfo {
			index: 7,
			start: None,
		});
		assert_eq!(crate::staking::ActiveEraIndex::get(), 7);
	});
}
