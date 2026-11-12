// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The direct bond's lifecycle: the staking hold always equals the ledger's
//! total, unbonded stake unlocks after exactly the bonding duration, nothing
//! but staking moves held funds, and a bond cannot pay the deprecated
//! `Controller` destination.

use super::{account, bond, offer};
use crate::{
	staking::params::BONDING_DURATION, test_utils::with_ext, AccountId, Balance, Balances, Runtime,
	RuntimeCall, RuntimeHoldReason, RuntimeOrigin, Staking,
};
use frame_support::{
	assert_noop, assert_ok,
	traits::fungible::{Inspect, InspectHold, Mutate},
};
use pallet_staking_async::RewardDestination;
use sp_runtime::{traits::Dispatchable, DispatchError};
use sp_staking::StakingInterface;

const UNIT: Balance = 1_000_000_000_000;

fn reason() -> RuntimeHoldReason {
	RuntimeHoldReason::Staking(pallet_staking_async::HoldReason::Staking)
}

fn held(who: &AccountId) -> Balance {
	Balances::balance_on_hold(&reason(), who)
}

fn ledger_total(who: &AccountId) -> Balance {
	<Staking as StakingInterface>::total_stake(who).unwrap_or_default()
}

fn at_era(index: u32) {
	pallet_staking_async::ActiveEra::<Runtime>::put(pallet_staking_async::ActiveEraInfo {
		index,
		start: None,
	});
	pallet_staking_async::CurrentEra::<Runtime>::put(index);
}

fn assert_hold_matches(who: &AccountId) {
	assert_eq!(held(who), ledger_total(who), "hold == ledger total");
}

/// Every step keeps the hold equal to the ledger's total; a chunk unlocks
/// after exactly the bonding duration; rebond restores only what unlocks.
#[test]
fn the_staking_hold_follows_the_ledger_through_its_lifecycle() {
	with_ext(|| {
		pallet_staking_async::MinNominatorBond::<Runtime>::put(UNIT);
		at_era(5);
		let (who, validator) = (account(1), account(2));
		bond(&validator, 100 * UNIT);
		offer(&validator);
		Balances::set_balance(&who, 100 * UNIT);
		assert_ok!(Staking::bond(
			RuntimeOrigin::signed(who.clone()),
			50 * UNIT,
			RewardDestination::Staked
		));
		assert_hold_matches(&who);
		assert_ok!(Staking::nominate(
			RuntimeOrigin::signed(who.clone()),
			vec![validator.clone()]
		));

		// `bond_extra` takes at most what is free above the existential deposit.
		let ed = Balances::minimum_balance();
		assert_ok!(Staking::bond_extra(
			RuntimeOrigin::signed(who.clone()),
			u128::MAX
		));
		assert_eq!(ledger_total(&who), 100 * UNIT - ed);
		assert_eq!(Balances::balance(&who), ed);
		assert_hold_matches(&who);

		assert_ok!(Staking::unbond(
			RuntimeOrigin::signed(who.clone()),
			30 * UNIT
		));
		assert_hold_matches(&who);
		assert_ok!(Staking::rebond(
			RuntimeOrigin::signed(who.clone()),
			u128::MAX
		));
		let ledger = pallet_staking_async::Ledger::<Runtime>::get(&who).unwrap();
		assert_eq!(
			(ledger.active, ledger.total),
			(100 * UNIT - ed, 100 * UNIT - ed)
		);
		assert!(
			ledger.unlocking.is_empty(),
			"rebond restores only what unlocks"
		);

		assert_ok!(Staking::unbond(
			RuntimeOrigin::signed(who.clone()),
			30 * UNIT
		));
		at_era(5 + BONDING_DURATION - 1);
		assert_ok!(Staking::withdraw_unbonded(
			RuntimeOrigin::signed(who.clone()),
			0
		));
		assert_eq!(
			ledger_total(&who),
			100 * UNIT - ed,
			"one era early: nothing unlocks"
		);
		at_era(5 + BONDING_DURATION);
		assert_ok!(Staking::withdraw_unbonded(
			RuntimeOrigin::signed(who.clone()),
			0
		));
		assert_eq!(ledger_total(&who), 70 * UNIT - ed);
		assert_eq!(Balances::balance(&who), 30 * UNIT + ed);
		assert_hold_matches(&who);
	});
}

/// Balance transfers move free funds only: neither `transfer_all` nor an
/// over-sized transfer touches the staking hold.
#[test]
fn transfers_never_spend_the_staking_hold() {
	with_ext(|| {
		let (who, to) = (account(1), account(3));
		bond(&who, 40 * UNIT);
		let free = Balances::balance(&who);
		assert!(Balances::transfer_allow_death(
			RuntimeOrigin::signed(who.clone()),
			to.clone(),
			free + 1
		)
		.is_err());
		for keep_alive in [true, false] {
			assert_ok!(Balances::transfer_all(
				RuntimeOrigin::signed(who.clone()),
				to.clone(),
				keep_alive
			));
		}
		assert!(Balances::balance(&who) <= Balances::minimum_balance());
		assert_eq!(held(&who), 40 * UNIT);
		assert_hold_matches(&who);
		assert!(frame_system::Pallet::<Runtime>::account_exists(&who));
	});
}

/// `set_payee` refuses the deprecated `Controller` destination; so does the
/// call filter for `bond`, which upstream does not check.
#[test]
fn a_bond_cannot_pay_the_controller_destination() {
	with_ext(|| {
		let who = account(1);
		Balances::set_balance(&who, 100 * UNIT);
		#[allow(deprecated)]
		let call = RuntimeCall::Staking(pallet_staking_async::Call::bond {
			value: 10 * UNIT,
			payee: RewardDestination::Controller,
		});
		assert_noop!(
			call.dispatch(RuntimeOrigin::signed(who.clone()))
				.map_err(|e| e.error),
			DispatchError::from(frame_system::Error::<Runtime>::CallFiltered)
		);
		let staked = RuntimeCall::Staking(pallet_staking_async::Call::bond {
			value: 10 * UNIT,
			payee: RewardDestination::Staked,
		});
		assert_ok!(staked.dispatch(RuntimeOrigin::signed(who.clone())));
	});
}
