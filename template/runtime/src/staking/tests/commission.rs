//! The commission ceiling: none by default, set by governance on-chain, and
//! validators above a lowered one clamped to it at the next session report.

use super::account as numbered;
use crate::{
	staking::commission::clamp_to_ceiling,
	test_utils::{
		account,
		blocks::{next_session, run_to_era},
		network::with_validators,
		with_ext,
	},
	AccountId, Runtime, RuntimeEvent, RuntimeOrigin, Staking, System,
};
use frame_support::{assert_noop, assert_ok};
use pallet_staking_async::{ValidatorPrefs, Validators};
use sp_keyring::Sr25519Keyring::{Alice, Bob, Charlie};
use sp_runtime::{DispatchError, Perbill};

fn prefs(commission: Perbill) -> ValidatorPrefs {
	ValidatorPrefs {
		commission,
		blocked: false,
	}
}

fn commission(who: &AccountId) -> Perbill {
	Validators::<Runtime>::get(who).commission
}

fn prefs_set_events() -> Vec<(AccountId, Perbill)> {
	System::events()
		.into_iter()
		.filter_map(|record| match record.event {
			RuntimeEvent::Staking(pallet_staking_async::Event::ValidatorPrefsSet {
				stash,
				prefs,
			}) => Some((stash, prefs.commission)),
			_ => None,
		})
		.collect()
}

#[test]
fn lowering_the_ceiling_clamps_validators_above_it_at_the_next_session_report() {
	with_validators(|| {
		let (alice, bob, charlie) = (account(Alice), account(Bob), account(Charlie));
		for (who, percent) in [(&alice, 50), (&bob, 10), (&charlie, 5)] {
			assert_ok!(Staking::validate(
				RuntimeOrigin::signed(who.clone()),
				prefs(Perbill::from_percent(percent))
			));
		}

		let ceiling = Perbill::from_percent(10);
		assert_noop!(
			Staking::set_max_commission(RuntimeOrigin::signed(alice.clone()), ceiling),
			DispatchError::BadOrigin
		);
		assert_ok!(Staking::set_max_commission(RuntimeOrigin::root(), ceiling));
		assert_eq!(commission(&alice), Perbill::from_percent(50));

		System::reset_events();
		next_session();
		assert_eq!(commission(&alice), ceiling);
		assert_eq!(commission(&bob), ceiling);
		assert_eq!(commission(&charlie), Perbill::from_percent(5));
		assert_eq!(prefs_set_events(), vec![(alice.clone(), ceiling)]);

		// The next era staking plans is elected and paid with the clamped commission.
		let next = pallet_staking_async::CurrentEra::<Runtime>::get().unwrap_or_default() + 1;
		run_to_era(next);
		assert_eq!(
			pallet_staking_async::ErasValidatorPrefs::<Runtime>::get(next, &alice).commission,
			ceiling
		);
	});
}

/// One read without a ceiling; below 100 %, a read per candidate and a read
/// and a write per clamped one (`Validators` is a counted map).
#[test]
fn the_clamp_reads_every_candidate_and_writes_only_those_above() {
	with_ext(|| {
		let db = <Runtime as frame_system::Config>::DbWeight::get();
		for (n, percent) in [(1, 30), (2, 20), (3, 0)] {
			Validators::<Runtime>::insert(numbered(n), prefs(Perbill::from_percent(percent)));
		}
		assert_eq!(clamp_to_ceiling(), db.reads(1));
		assert_eq!(commission(&numbered(1)), Perbill::from_percent(30));

		pallet_staking_async::MaxCommission::<Runtime>::put(Perbill::from_percent(20));
		assert_eq!(clamp_to_ceiling(), db.reads_writes(3 + 2 + 1, 1));
		assert_eq!(commission(&numbered(1)), Perbill::from_percent(20));
		assert_eq!(commission(&numbered(2)), Perbill::from_percent(20));
		assert_eq!(commission(&numbered(3)), Perbill::zero());
	});
}

/// `set_staking_configs` is root's and skips the check `set_min_commission`
/// makes against the ceiling. A floor above the ceiling refuses every new
/// commission (staking below the floor, the ceiling above it), and the clamp
/// still lowers candidates to the ceiling, below the floor: the ceiling is what
/// the snapshot filter enforces, so they stay electable rather than none being.
#[test]
fn a_floor_above_the_ceiling_refuses_candidacies_and_the_ceiling_wins() {
	use super::{approve, bond, elected_candidates, set_keys};
	use crate::staking::{admission::Inadmissible, candidacy::check_candidacy};
	use pallet_staking_async::{ConfigOp, Error};
	with_ext(|| {
		let who = numbered(1);
		set_keys(&who);
		approve(&who);
		bond(&who, 1_000);
		assert_ok!(Staking::validate(
			RuntimeOrigin::signed(who.clone()),
			prefs(Perbill::from_percent(30))
		));
		let (floor, ceiling) = (Perbill::from_percent(25), Perbill::from_percent(20));
		assert_ok!(Staking::set_max_commission(RuntimeOrigin::root(), ceiling));
		assert_noop!(
			Staking::set_min_commission(RuntimeOrigin::root(), floor),
			Error::<Runtime>::CommissionTooHigh
		);
		assert_ok!(Staking::set_staking_configs(
			RuntimeOrigin::root(),
			ConfigOp::Noop,
			ConfigOp::Noop,
			ConfigOp::Noop,
			ConfigOp::Noop,
			ConfigOp::Noop,
			ConfigOp::Set(floor),
			ConfigOp::Noop,
			ConfigOp::Noop,
		));

		assert_noop!(
			Staking::validate(RuntimeOrigin::signed(who.clone()), prefs(ceiling)),
			Error::<Runtime>::CommissionTooLow
		);
		assert_eq!(
			check_candidacy(&who, &prefs(floor)),
			Err(Inadmissible::CommissionTooHigh)
		);

		clamp_to_ceiling();
		assert_eq!(commission(&who), ceiling);
		assert_eq!(elected_candidates(), vec![who]);
	});
}
