//! Who waits how long to leave: validators the full bonding duration, nominators
//! and pool members the shorter nominator time, since only validators are
//! slashed; an account that validated recently waits the full time whatever it
//! does now. Genesis turns nominator slashing off.

use crate::{
	genesis::{DEV_PRESET_ID, MAINNET_PRESET_ID, TESTNET_PRESET_ID},
	staking::params::{BONDING_DURATION, NOMINATOR_UNBOND_DURATION, TEST_MIN_VALIDATOR_BOND},
	test_utils::{
		account,
		blocks::{active_era, run_to_era},
		network::{charlie, genesis},
		with_preset,
	},
	Balances, Runtime, Staking,
};
use frame_support::{assert_ok, traits::fungible::Mutate};
use sp_keyring::Sr25519Keyring;
use sp_staking::StakingInterface;

/// The era `who`'s last unbonding chunk unlocks in.
fn unlocks_at(who: &crate::AccountId) -> u32 {
	pallet_staking_async::Ledger::<Runtime>::get(who)
		.and_then(|ledger| ledger.unlocking.last().map(|chunk| chunk.era))
		.expect("an unbonding chunk")
}

#[test]
fn every_preset_starts_with_nominators_unslashable() {
	for preset in [DEV_PRESET_ID, TESTNET_PRESET_ID, MAINNET_PRESET_ID] {
		with_preset(preset, || {
			assert!(
				!pallet_staking_async::AreNominatorsSlashable::<Runtime>::get(),
				"{preset}"
			);
			assert_eq!(
				pallet_staking_async::ErasNominatorsSlashable::<Runtime>::get(0),
				Some(false),
				"{preset}: the genesis era too"
			);
		});
	}
}

#[test]
fn a_nominator_unbonds_in_the_nominator_time() {
	genesis().execute_with(|| {
		let nominator = account(Sr25519Keyring::Ferdie);
		Balances::set_balance(&nominator, 2 * TEST_MIN_VALIDATOR_BOND);
		assert_ok!(<Staking as StakingInterface>::bond(
			&nominator,
			TEST_MIN_VALIDATOR_BOND,
			&nominator
		));
		assert_ok!(<Staking as StakingInterface>::nominate(
			&nominator,
			vec![charlie()]
		));
		run_to_era(1);
		assert_ok!(<Staking as StakingInterface>::unbond(
			&nominator,
			TEST_MIN_VALIDATOR_BOND
		));
		assert_eq!(
			unlocks_at(&nominator),
			active_era() + NOMINATOR_UNBOND_DURATION
		);
	});
}

#[test]
fn a_validator_unbonds_in_the_full_bonding_duration() {
	genesis().execute_with(|| {
		run_to_era(1);
		assert_ok!(<Staking as StakingInterface>::unbond(
			&charlie(),
			TEST_MIN_VALIDATOR_BOND
		));
		assert_eq!(unlocks_at(&charlie()), active_era() + BONDING_DURATION);
	});
}

/// A validator cannot dodge a slash by switching to nominating before it leaves.
#[test]
fn a_recent_validator_turned_nominator_still_waits_the_full_duration() {
	genesis().execute_with(|| {
		run_to_era(1);
		assert_ok!(<Staking as StakingInterface>::chill(&charlie()));
		assert_ok!(<Staking as StakingInterface>::nominate(
			&charlie(),
			vec![account(Sr25519Keyring::Alice)]
		));
		run_to_era(2);
		assert_ok!(<Staking as StakingInterface>::unbond(
			&charlie(),
			TEST_MIN_VALIDATOR_BOND
		));
		assert_eq!(unlocks_at(&charlie()), active_era() + BONDING_DURATION);
	});
}
