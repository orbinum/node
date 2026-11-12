// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! What each preset sets up for staking: the testnet's bonded validators and era 0,
//! mainnet's bonds, and no caps on nominators, pools or commission.

use super::{account, bond, offer};
use crate::{
	genesis::{DEV_PRESET_ID, MAINNET_PRESET_ID, TESTNET_PRESET_ID},
	staking::params::*,
	test_utils::with_preset,
	AccountId, Runtime, RuntimeOrigin, Session, Staking,
};
use frame_support::{assert_ok, traits::Get};
use sp_staking::StakingInterface;

#[test]
fn testnet_genesis_bonds_its_validators_and_opens_era_zero() {
	with_preset(TESTNET_PRESET_ID, || {
		let validators = Session::validators();
		assert_eq!(validators.len(), 3);
		for v in &validators {
			let stake = <Staking as StakingInterface>::stake(v).expect("bonded");
			assert_eq!(stake.active, TEST_MIN_VALIDATOR_BOND);
			assert!(pallet_staking_async::Validators::<Runtime>::contains_key(v));
		}
		assert_eq!(pallet_staking_async::ValidatorCount::<Runtime>::get(), 3);
		assert_eq!(crate::configs::staking::MinimumValidatorSetSize::get(), 2);
		assert_eq!(
			pallet_staking_async::MinValidatorBond::<Runtime>::get(),
			TEST_MIN_VALIDATOR_BOND
		);
		assert_eq!(
			pallet_staking_async::ForceEra::<Runtime>::get(),
			pallet_staking_async::Forcing::NotForcing
		);
		assert_eq!(pallet_staking_async::CurrentEra::<Runtime>::get(), Some(0));
		assert_eq!(
			pallet_staking_async::ActiveEra::<Runtime>::get().map(|era| era.index),
			Some(0)
		);
		assert_eq!(
			pallet_staking_async_ah_client::Mode::<Runtime>::get(),
			pallet_staking_async_ah_client::OperatingMode::Active
		);
	});
}

#[test]
fn mainnet_genesis_uses_tokenomics_bonds() {
	with_preset(MAINNET_PRESET_ID, || {
		assert_eq!(
			pallet_staking_async::MinValidatorBond::<Runtime>::get(),
			MAINNET_MIN_VALIDATOR_BOND
		);
		assert_eq!(
			pallet_staking_async::MinNominatorBond::<Runtime>::get(),
			MAINNET_MIN_NOMINATOR_BOND
		);
		assert_eq!(
			pallet_nomination_pools::MinCreateBond::<Runtime>::get(),
			MAINNET_POOL_MIN_CREATE_BOND
		);
	});
}

/// No network caps nominators or pools at genesis: the minimum bonds are the
/// anti-spam, and the election reads the most staked.
#[test]
fn no_preset_caps_nominators_or_pools() {
	for id in [DEV_PRESET_ID, TESTNET_PRESET_ID, MAINNET_PRESET_ID] {
		with_preset(id, || {
			assert_eq!(
				pallet_staking_async::MaxNominatorsCount::<Runtime>::get(),
				None,
				"{id}"
			);
			assert_eq!(pallet_nomination_pools::MaxPools::<Runtime>::get(), None);
			assert_eq!(
				pallet_nomination_pools::MaxPoolMembers::<Runtime>::get(),
				None
			);
			assert_eq!(
				pallet_nomination_pools::MaxPoolMembersPerPool::<Runtime>::get(),
				None
			);
		});
	}
}

/// Governance caps nominators on-chain and lifts the cap again; only root may.
#[test]
fn governance_caps_nominators_on_chain() {
	use pallet_staking_async::ConfigOp::{Noop, Remove, Set};
	let set_cap = |origin: RuntimeOrigin, cap| {
		Staking::set_staking_configs(origin, Noop, Noop, cap, Noop, Noop, Noop, Noop, Noop)
	};
	let nominate = |who: &AccountId| {
		let target = account(200);
		Staking::nominate(RuntimeOrigin::signed(who.clone()), vec![target])
	};
	with_preset(TESTNET_PRESET_ID, || {
		let target = account(200);
		bond(&target, TEST_MIN_VALIDATOR_BOND);
		offer(&target);
		for n in 1..=3 {
			bond(&account(n), TEST_MIN_NOMINATOR_BOND);
		}
		assert!(set_cap(RuntimeOrigin::signed(account(1)), Set(1)).is_err());

		let existing = pallet_staking_async::Nominators::<Runtime>::count();
		assert_ok!(set_cap(RuntimeOrigin::root(), Set(existing + 1)));
		assert_ok!(nominate(&account(1)));
		assert_eq!(
			nominate(&account(2)),
			Err(pallet_staking_async::Error::<Runtime>::TooManyNominators.into())
		);
		// A nominator already counted may change its targets.
		assert_ok!(nominate(&account(1)));

		assert_ok!(set_cap(RuntimeOrigin::root(), Remove));
		assert_eq!(
			pallet_staking_async::MaxNominatorsCount::<Runtime>::get(),
			None
		);
		assert_ok!(nominate(&account(2)));
		assert_ok!(nominate(&account(3)));
	});
}

/// No preset sets a commission ceiling: staking's `MaxCommission` stays at its
/// 100 % default and pools have no `GlobalMaxCommission`. Governance sets one
/// on-chain, and `validate` then refuses a commission above it.
#[test]
fn no_preset_caps_commission() {
	use crate::genesis::LOCAL_PRESET_ID;
	use frame_support::assert_noop;
	use sp_runtime::Perbill;

	for id in [
		DEV_PRESET_ID,
		LOCAL_PRESET_ID,
		TESTNET_PRESET_ID,
		MAINNET_PRESET_ID,
	] {
		with_preset(id, || {
			assert_eq!(
				pallet_staking_async::MaxCommission::<Runtime>::get(),
				Perbill::one(),
				"{id}"
			);
			assert_eq!(
				pallet_nomination_pools::GlobalMaxCommission::<Runtime>::get(),
				None,
				"{id}"
			);
		});
	}
	with_preset(TESTNET_PRESET_ID, || {
		let who = account(9);
		bond(&who, TEST_MIN_VALIDATOR_BOND);
		let prefs = |commission| pallet_staking_async::ValidatorPrefs {
			commission,
			blocked: false,
		};
		assert_ok!(Staking::validate(
			RuntimeOrigin::signed(who.clone()),
			prefs(Perbill::one())
		));
		let ceiling = Perbill::from_percent(20);
		assert_ok!(Staking::set_max_commission(RuntimeOrigin::root(), ceiling));
		assert_noop!(
			Staking::validate(
				RuntimeOrigin::signed(who.clone()),
				prefs(Perbill::from_parts(ceiling.deconstruct() + 1))
			),
			pallet_staking_async::Error::<Runtime>::CommissionTooHigh
		);
		assert_ok!(Staking::validate(
			RuntimeOrigin::signed(who),
			prefs(ceiling)
		));
	});
}
