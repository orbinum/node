//! `InitStaking` on a chain that ran without staking: the set stays, era 0 opens
//! at the current session, the session side starts reporting, and no election
//! is asked for until governance forces one.

use crate::{
	migrations::InitStaking,
	staking::params::{
		POOL_MIN_JOIN_BOND, TEST_MIN_NOMINATOR_BOND, TEST_MIN_VALIDATOR_BOND,
		TEST_POOL_MIN_CREATE_BOND,
	},
	test_utils::{with_ext, with_preset},
	AccountId, Runtime, Session, ValidatorSet,
};
use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade};
use pallet_nomination_pools as pools;
use pallet_staking_async as staking;
use pallet_staking_async_ah_client as ah_client;
use pallet_staking_async_rc_client::AHStakingInterface;

fn live_chain() {
	// A spec 20 chain: no staking era, validator set at storage version 0.
	frame_support::traits::StorageVersion::new(0).put::<ValidatorSet>();
	staking::CurrentEra::<Runtime>::kill();
	let set: Vec<AccountId> = (1..=3u8).map(|n| AccountId::from([n; 32])).collect();
	pallet_session::Validators::<Runtime>::put(set);
	pallet_session::CurrentIndex::<Runtime>::put(5);
	pallet_timestamp::Now::<Runtime>::put(1_000);
}

#[test]
fn opens_era_zero_and_keeps_the_set() {
	with_ext(|| {
		live_chain();
		InitStaking::on_runtime_upgrade();

		assert_eq!(staking::CurrentEra::<Runtime>::get(), Some(0));
		assert_eq!(
			staking::ActiveEra::<Runtime>::get().map(|e| (e.index, e.start)),
			Some((0, Some(1_000)))
		);
		assert_eq!(
			staking::BondedEras::<Runtime>::get().into_inner(),
			vec![(0, 5)]
		);
		assert_eq!(staking::ValidatorCount::<Runtime>::get(), 3);
		assert_eq!(
			staking::MinValidatorBond::<Runtime>::get(),
			TEST_MIN_VALIDATOR_BOND
		);
		assert_eq!(
			staking::MinNominatorBond::<Runtime>::get(),
			TEST_MIN_NOMINATOR_BOND
		);
		// No caps on nominators, pools, members or commission, as at genesis.
		assert_eq!(
			staking::MaxCommission::<Runtime>::get(),
			sp_runtime::Perbill::one()
		);
		assert_eq!(staking::MaxNominatorsCount::<Runtime>::get(), None);
		assert_eq!(pools::MaxPools::<Runtime>::get(), None);
		assert_eq!(pools::MaxPoolMembers::<Runtime>::get(), None);
		assert_eq!(pools::MaxPoolMembersPerPool::<Runtime>::get(), None);
		// Pools get the bonds a new chain's genesis sets.
		assert_eq!(pools::MinJoinBond::<Runtime>::get(), POOL_MIN_JOIN_BOND);
		assert_eq!(
			pools::MinCreateBond::<Runtime>::get(),
			TEST_POOL_MIN_CREATE_BOND
		);
		assert_eq!(pools::GlobalMaxCommission::<Runtime>::get(), None);
		assert_eq!(
			ah_client::Mode::<Runtime>::get(),
			ah_client::OperatingMode::Active
		);
		assert_eq!(ah_client::ValidatorSetAppliedAt::<Runtime>::get(), Some(5));
		assert_eq!(ValidatorSet::on_chain_storage_version(), 1);
		assert_eq!(
			staking::ForceEra::<Runtime>::get(),
			staking::Forcing::ForceNone
		);

		// Session reports go on past the era length without staking planning
		// an era: no election until governance forces one.
		for end_index in 5..(5 + 100) {
			crate::Staking::on_relay_session_report(
				pallet_staking_async_rc_client::SessionReport {
					end_index,
					validator_points: vec![],
					activation_timestamp: None,
					leftover: false,
				},
			);
			assert_eq!(staking::CurrentEra::<Runtime>::get(), Some(0));
		}
		assert_eq!(
			pallet_paged_election::CurrentPhase::<Runtime>::get(),
			pallet_paged_election::Phase::Off
		);
		assert_eq!(Session::validators().len(), 3);
	});
}

#[test]
fn is_idempotent() {
	with_ext(|| {
		live_chain();
		InitStaking::on_runtime_upgrade();
		staking::ValidatorCount::<Runtime>::put(7);

		let weight = InitStaking::on_runtime_upgrade();
		assert_eq!(
			staking::ValidatorCount::<Runtime>::get(),
			7,
			"second run wrote"
		);
		assert_eq!(
			weight,
			<Runtime as frame_system::Config>::DbWeight::get().reads(2)
		);
	});
}

#[test]
fn leaves_a_chain_built_with_staking_alone() {
	with_ext(|| {
		staking::CurrentEra::<Runtime>::put(3);
		InitStaking::on_runtime_upgrade();
		assert!(staking::BondedEras::<Runtime>::get().is_empty());
		assert_eq!(
			ah_client::Mode::<Runtime>::get(),
			ah_client::OperatingMode::Passive
		);
	});
}

/// A new chain opens era 0 at genesis and starts at storage version 1: the
/// migration must not treat it as a spec 20 chain (it would force eras off and
/// reset the bonds' minimums).
#[test]
fn leaves_a_new_chain_alone() {
	with_preset(crate::genesis::TESTNET_PRESET_ID, || {
		assert_eq!(ValidatorSet::on_chain_storage_version(), 1);
		staking::CurrentEra::<Runtime>::kill();
		let force = staking::ForceEra::<Runtime>::get();
		let min = staking::MinValidatorBond::<Runtime>::get();
		InitStaking::on_runtime_upgrade();
		assert_eq!(staking::ForceEra::<Runtime>::get(), force);
		assert_eq!(staking::MinValidatorBond::<Runtime>::get(), min);
		assert!(staking::CurrentEra::<Runtime>::get().is_none());
	});
}

/// try-runtime's checks follow the migration: they verify era 0 where it ran and
/// pass where it did nothing (a chain with staking already).
#[cfg(feature = "try-runtime")]
#[test]
fn try_runtime_checks_pass_whether_it_runs_or_not() {
	let upgrade = || -> Result<(), sp_runtime::TryRuntimeError> {
		let state = InitStaking::pre_upgrade()?;
		InitStaking::on_runtime_upgrade();
		InitStaking::post_upgrade(state)
	};
	with_ext(|| {
		live_chain();
		assert_eq!(upgrade(), Ok(()));
	});
	with_preset(crate::genesis::TESTNET_PRESET_ID, || {
		staking::CurrentEra::<Runtime>::put(3);
		assert_eq!(upgrade(), Ok(()));
		assert_eq!(staking::CurrentEra::<Runtime>::get(), Some(3));
	});
}
