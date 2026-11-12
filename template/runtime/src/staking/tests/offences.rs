//! A GRANDPA equivocation, from report to slash: the proof, the offence, the ban
//! and chill it triggers at once, the offence's way through ah-client to
//! staking, the deferred slash, and its cancellation.
//!
//! Three validators (Alice, Bob, Charlie) with dev keys; Charlie equivocates.

use crate::test_utils::{
	blocks::{run_to_era, settle},
	network::{charlie, prevote_equivocation, report_charlie, with_validators},
};
use crate::{
	economy::GovernanceAccount,
	staking::params::{SLASH_DEFER_DURATION, SLASH_REWARD_FRACTION, TEST_MIN_VALIDATOR_BOND},
	test_utils::account,
	AccountId, AutoPayout, Balance, Balances, Grandpa, Historical, Runtime, RuntimeOrigin, Staking,
	ValidatorSet,
};
use frame_support::{
	assert_noop, assert_ok,
	traits::{fungible::Inspect, KeyOwnerProofSystem},
};
use sp_consensus_grandpa::{AuthorityId as GrandpaId, KEY_TYPE};
use sp_core::crypto::UncheckedFrom;
use sp_keyring::{Ed25519Keyring, Sr25519Keyring};
use sp_staking::StakingInterface;

/// A proof can be built for any key; only one for a session validator checks
/// out, which is what an equivocation report needs.
#[test]
fn key_ownership_proof_only_checks_for_session_validators() {
	with_validators(|| {
		let check = |key: Ed25519Keyring| {
			let id = (KEY_TYPE, GrandpaId::unchecked_from(key.public().0));
			let proof = Historical::prove(id.clone()).expect("a proof is always built");
			Historical::check_proof(id, proof).is_some()
		};
		assert!(check(Ed25519Keyring::Alice));
		assert!(!check(Ed25519Keyring::Ferdie));
	});
}

/// The era Charlie's slash is due in: era 1's, deferred.
const APPLY_ERA: u32 = 1 + SLASH_DEFER_DURATION;

/// The deferred slash staking recorded for Charlie: its key.
fn charlie_slash() -> Option<(AccountId, sp_runtime::Perbill, u32)> {
	pallet_staking_async::UnappliedSlashes::<Runtime>::iter_prefix(APPLY_ERA)
		.map(|(key, _)| key)
		.find(|(who, _, _)| *who == charlie())
}

#[test]
fn equivocation_bans_chills_and_defers_a_slash() {
	with_validators(|| {
		assert!(pallet_staking_async::Validators::<Runtime>::contains_key(
			charlie()
		));
		assert_ok!(report_charlie());
		assert!(ValidatorSet::is_banned(&charlie()));
		assert!(!pallet_staking_async::Validators::<Runtime>::contains_key(
			charlie()
		));

		// ah-client sends the offence to staking, which defers the slash.
		settle();
		let (_, fraction, _) = charlie_slash().expect("a deferred slash");
		// One offender of three is GRANDPA's 100 %, capped.
		assert_eq!(fraction, crate::staking::params::MAX_SLASH_FRACTION);

		// The same equivocation cannot be reported twice.
		assert!(report_charlie().is_err());
	});
}

#[test]
fn a_slash_cannot_be_escaped_by_unbonding() {
	with_validators(|| {
		// Rewards would change the balances checked below.
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		let issuance = Balances::total_issuance();
		// An unsigned report's reporter is the author of the block that has it.
		let reporter = pallet_authorship::Pallet::<Runtime>::author().expect("an author");
		let reporter_before = Balances::balance(&reporter);
		assert_ok!(report_charlie());
		// Charlie unbonds everything right after the report.
		assert_ok!(<Staking as StakingInterface>::unbond(
			&charlie(),
			TEST_MIN_VALIDATOR_BOND
		));

		run_to_era(APPLY_ERA);
		settle();
		assert!(charlie_slash().is_none(), "applied");

		// One offender out of three validators: (3 × 1/3)² = the whole exposure,
		// capped at `MAX_SLASH_FRACTION`; the rest of the bond is what stays.
		let left = <Staking as StakingInterface>::total_stake(&charlie()).unwrap_or_default();
		let cap_left = TEST_MIN_VALIDATOR_BOND
			- crate::staking::params::MAX_SLASH_FRACTION * TEST_MIN_VALIDATOR_BOND;
		assert!(
			left <= cap_left + TEST_MIN_VALIDATOR_BOND / 1_000_000,
			"unbonding funds escaped: {left}"
		);
		// The reporter's share (`SLASH_REWARD_FRACTION`) to the reporter, the
		// rest to governance.
		let reward = Balances::balance(&reporter) - reporter_before;
		let governance = Balances::balance(&GovernanceAccount::get());
		assert_eq!(
			governance + reward + left,
			TEST_MIN_VALIDATOR_BOND,
			"the whole slash is accounted for"
		);
		let slashed = TEST_MIN_VALIDATOR_BOND - left;
		assert!(
			reward.abs_diff(SLASH_REWARD_FRACTION * slashed) <= 1,
			"reward {reward}"
		);
		// Moved, not burned.
		assert_eq!(Balances::total_issuance(), issuance);
		// Still banned: the ban outlives the deferral.
		assert!(ValidatorSet::is_banned(&charlie()));
	});
}

#[test]
fn governance_can_cancel_the_slash_but_the_ban_stays() {
	with_validators(|| {
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		assert_ok!(report_charlie());
		settle();
		let (who, fraction, _) = charlie_slash().expect("a deferred slash");
		assert_ok!(Staking::cancel_deferred_slash(
			RuntimeOrigin::root(),
			APPLY_ERA,
			vec![(who, fraction)]
		));

		run_to_era(APPLY_ERA);
		settle();
		assert!(charlie_slash().is_none());
		assert_eq!(
			<Staking as StakingInterface>::total_stake(&charlie()),
			Ok(TEST_MIN_VALIDATOR_BOND),
			"cancelled: nothing slashed"
		);
		assert_eq!(Balances::balance(&GovernanceAccount::get()), 0);
		assert!(ValidatorSet::is_banned(&charlie()));
	});
}

/// The ban has no term: eras stalled far past what a term in blocks covered
/// (the bonding period plus the slash's era) leave the offender banned, until
/// governance lifts it; then it must offer itself again.
#[test]
fn an_equivocation_ban_lasts_until_governance_lifts_it() {
	use super::elected_candidates;
	use crate::staking::{
		admission::{check, Inadmissible},
		candidacy::check_candidacy,
		params::{BONDING_DURATION, SESSIONS_PER_ERA, SESSION_PERIOD},
	};
	use pallet_staking_async::ValidatorPrefs;
	use pallet_validator_set::BanTerm;
	with_validators(|| {
		assert_ok!(report_charlie());
		assert_eq!(
			pallet_validator_set::Bans::<Runtime>::get(charlie()),
			Some(BanTerm::Permanent)
		);
		// Only the offender.
		assert!(!ValidatorSet::is_banned(&account(Sr25519Keyring::Alice)));

		assert_ok!(Staking::force_no_eras(RuntimeOrigin::root()));
		let block_term = (BONDING_DURATION + 1) * SESSIONS_PER_ERA * SESSION_PERIOD;
		let now = frame_system::Pallet::<Runtime>::block_number();
		frame_system::Pallet::<Runtime>::set_block_number(now + 10 * block_term);
		assert_eq!(
			check(&ValidatorSet::admission(), &charlie()),
			Err(Inadmissible::Banned)
		);
		assert_eq!(
			check_candidacy(&charlie(), &ValidatorPrefs::default()),
			Err(Inadmissible::Banned)
		);

		assert_ok!(ValidatorSet::unban_validator(
			RuntimeOrigin::root(),
			charlie()
		));
		assert!(!elected_candidates().contains(&charlie()), "still chilled");
		assert_eq!(
			check_candidacy(&charlie(), &ValidatorPrefs::default()),
			Ok(())
		);
		assert_ok!(Staking::validate(
			RuntimeOrigin::signed(charlie()),
			ValidatorPrefs::default()
		));
		assert!(elected_candidates().contains(&charlie()));
	});
}

/// The reporter's share is computed on the whole slash, nominators' included,
/// and the offender may report itself. With nominators at 20 times Charlie's own
/// stake, Charlie reporting itself from an account it controls loses more than
/// the report pays.
#[test]
fn self_report_is_not_profitable() {
	use crate::{test_utils::network::genesis, RuntimeCall};
	use frame_support::traits::fungible::Mutate;
	use sp_runtime::traits::Dispatchable;
	genesis().execute_with(|| {
		super::nominators_slashable();
		let nominator = account(Sr25519Keyring::Ferdie);
		let backing = 20 * TEST_MIN_VALIDATOR_BOND;
		Balances::set_balance(&nominator, 2 * backing);
		assert_ok!(<Staking as StakingInterface>::bond(
			&nominator, backing, &nominator
		));
		assert_ok!(<Staking as StakingInterface>::nominate(
			&nominator,
			vec![charlie()]
		));
		run_to_era(1);
		let exposed = pallet_staking_async::ErasStakersOverview::<Runtime>::get(1, charlie())
			.expect("Charlie exposed in era 1");
		assert!(exposed.total > 21 * TEST_MIN_VALIDATOR_BOND * 999 / 1000);
		assert!(exposed.own < TEST_MIN_VALIDATOR_BOND + 1);

		// Rewards would change the balances checked below.
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		let reporter = account(Sr25519Keyring::Dave);
		let holdings = || Balances::total_balance(&charlie()) + Balances::total_balance(&reporter);
		let before = holdings();

		let proof = prevote_equivocation(Ed25519Keyring::Charlie, Grandpa::current_set_id());
		let key_owner_proof = Historical::prove((
			KEY_TYPE,
			GrandpaId::unchecked_from(Ed25519Keyring::Charlie.public().0),
		))
		.unwrap();
		let report = RuntimeCall::Grandpa(pallet_grandpa::Call::report_equivocation {
			equivocation_proof: Box::new(proof),
			key_owner_proof,
		});
		assert_ok!(report.dispatch(RuntimeOrigin::signed(reporter.clone())));

		run_to_era(APPLY_ERA);
		settle();
		assert!(charlie_slash().is_none(), "applied");
		assert!(Balances::total_balance(&reporter) > 0, "the report paid");
		assert!(
			holdings() <= before,
			"self-report paid {} more than it cost",
			holdings() - before
		);
	});
}

#[test]
fn an_unsigned_report_needs_no_origin_but_rejects_signed() {
	with_validators(|| {
		let proof = prevote_equivocation(Ed25519Keyring::Charlie, Grandpa::current_set_id());
		let key_owner = Historical::prove((
			KEY_TYPE,
			GrandpaId::unchecked_from(Ed25519Keyring::Charlie.public().0),
		))
		.unwrap();
		assert_noop!(
			Grandpa::report_equivocation_unsigned(
				RuntimeOrigin::signed(account(Sr25519Keyring::Alice)),
				Box::new(proof),
				key_owner
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

/// By default only the offender's own stake is slashed: a nominator backing it is
/// not, and keeps its whole bond.
#[test]
fn a_slash_takes_the_validator_own_stake_not_its_nominators() {
	use crate::test_utils::network::genesis;
	use frame_support::traits::fungible::Mutate;
	genesis().execute_with(|| {
		let nominator = account(Sr25519Keyring::Ferdie);
		let backing = 10 * TEST_MIN_VALIDATOR_BOND;
		Balances::set_balance(&nominator, backing);
		assert_ok!(<Staking as StakingInterface>::bond(
			&nominator, backing, &nominator
		));
		assert_ok!(<Staking as StakingInterface>::nominate(
			&nominator,
			vec![charlie()]
		));
		run_to_era(2);
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		assert!(
			pallet_staking_async::ErasStakersOverview::<Runtime>::get(2, charlie())
				.is_some_and(|exposure| exposure.total > backing)
		);

		assert_ok!(report_charlie());
		settle();
		let slashes: Vec<_> =
			pallet_staking_async::UnappliedSlashes::<Runtime>::iter_values().collect();
		assert!(!slashes.is_empty(), "the validator is slashed");
		assert!(slashes
			.iter()
			.all(|slash| slash.own > 0 && slash.others.is_empty()));

		run_to_era(2 + SLASH_DEFER_DURATION + 1);
		settle();
		assert_eq!(
			<Staking as StakingInterface>::stake(&nominator).map(|s| s.total),
			Ok(backing),
			"the nominator keeps its bond"
		);
	});
}

/// Stake unbonded in the era before the offence, once the election has exposed
/// it for the offence's era, unlocks an era earlier than stake unbonded in the
/// offence's own era. The slash must still land before it can be withdrawn,
/// even by a withdrawal in the very block its unlock era starts.
#[test]
fn stake_unbonded_before_the_offence_era_cannot_outrun_its_slash() {
	use crate::{staking::params::BONDING_DURATION, test_utils::network::genesis};
	use frame_support::traits::fungible::Mutate;
	genesis().execute_with(|| {
		super::nominators_slashable();
		let nominator = account(Sr25519Keyring::Ferdie);
		let backing = 10 * TEST_MIN_VALIDATOR_BOND;
		Balances::set_balance(&nominator, backing);
		assert_ok!(<Staking as StakingInterface>::bond(
			&nominator, backing, &nominator
		));
		assert_ok!(<Staking as StakingInterface>::nominate(
			&nominator,
			vec![charlie()]
		));
		run_to_era(1);
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));

		// Era 2's exposures are stored while era 1 runs; both then leave.
		while pallet_staking_async::ErasStakersOverview::<Runtime>::get(2, charlie()).is_none()
			&& crate::test_utils::blocks::active_era() == 1
		{
			crate::test_utils::blocks::next_session();
		}
		assert_eq!(crate::test_utils::blocks::active_era(), 1);
		let exposed = pallet_staking_async::ErasStakersOverview::<Runtime>::get(2, charlie())
			.expect("era 2 exposed");
		assert!(exposed.total > backing);
		assert_ok!(<Staking as StakingInterface>::unbond(&nominator, backing));
		assert_ok!(<Staking as StakingInterface>::unbond(
			&charlie(),
			TEST_MIN_VALIDATOR_BOND
		));

		run_to_era(2);
		let issuance = Balances::total_issuance();
		assert_ok!(report_charlie());
		settle();
		let due: Balance = pallet_staking_async::UnappliedSlashes::<Runtime>::iter_values()
			.map(|slash| slash.own + slash.others.iter().map(|(_, value)| value).sum::<Balance>())
			.sum();
		assert!(due > backing, "the slash covers the nominator: {due}");
		let holdings = || Balances::total_balance(&charlie()) + Balances::total_balance(&nominator);
		let before = holdings();

		// Withdraw in the block that starts the unlock era, before any later hook.
		run_to_era(1 + BONDING_DURATION);
		for who in [&nominator, &charlie()] {
			let _ = Staking::withdraw_unbonded(RuntimeOrigin::signed(who.clone()), 0);
		}
		settle();
		assert_eq!(
			pallet_staking_async::UnappliedSlashes::<Runtime>::iter().count(),
			0,
			"every slash applied"
		);
		let slashed = before - holdings();
		assert!(
			slashed.abs_diff(due) <= 2,
			"slashed {slashed} of {due}: unbonded stake escaped"
		);
		assert_eq!(Balances::total_issuance(), issuance, "moved, not burned");
	});
}

/// A validator of the current or the queued session cannot change its session
/// keys: they are what an equivocation is proven against. Charlie's report
/// still checks out sessions later; an account out of the set rotates freely.
#[test]
fn validators_in_use_cannot_change_their_session_keys() {
	use super::admission::submit;
	use crate::{
		staking::candidacy::{CheckValidatorCandidacy, KEYS_IN_USE},
		test_utils::blocks::next_session,
		RuntimeCall,
	};
	use sp_runtime::traits::TransactionExtension;
	with_validators(|| {
		let keys = crate::opaque::SessionKeys {
			aura: sp_core::sr25519::Public::from_raw([7; 32]).into(),
			grandpa: sp_core::ed25519::Public::from_raw([7; 32]).into(),
		};
		let set_keys = RuntimeCall::Session(pallet_session::Call::set_keys {
			keys: keys.clone(),
			proof: vec![],
		});
		let purge_keys = RuntimeCall::Session(pallet_session::Call::purge_keys {});
		assert_eq!(submit(&charlie(), &set_keys), Err(KEYS_IN_USE));
		assert_eq!(submit(&charlie(), &purge_keys), Err(KEYS_IN_USE));

		let outsider = account(Sr25519Keyring::Dave);
		assert_eq!(submit(&outsider, &set_keys), Ok(()));
		// Queued for the next session: its keys are in use too.
		pallet_session::QueuedKeys::<Runtime>::mutate(|queued| {
			queued.push((outsider.clone(), keys))
		});
		assert_eq!(submit(&outsider, &set_keys), Err(KEYS_IN_USE));
		assert!(CheckValidatorCandidacy.weight(&set_keys).ref_time() > 0);
		pallet_session::QueuedKeys::<Runtime>::mutate(|queued| {
			queued.retain(|(who, _)| *who != outsider)
		});

		next_session();
		next_session();
		assert_ok!(report_charlie());
	});
}

/// A signed report of an offender already handed to staking in the era, in a
/// time slot no other offender shares, changes no slash: it is refused, even in
/// the report's own block, and pays its fee. Another offender in the era is
/// still heard.
#[test]
fn a_repeat_report_in_the_same_era_is_refused() {
	use crate::test_utils::network::report_signed_in_round;
	use frame_support::dispatch::Pays;
	with_validators(|| {
		let reporter = account(Sr25519Keyring::Dave);
		assert_ok!(report_signed_in_round(
			&reporter,
			Ed25519Keyring::Charlie,
			1
		));
		let reports = pallet_offences::Reports::<Runtime>::iter().count();
		let repeat = report_signed_in_round(&reporter, Ed25519Keyring::Charlie, 2)
			.expect_err("a repeat in the same block");
		assert_eq!(repeat.post_info.pays_fee, Pays::Yes);
		settle();
		assert!(report_signed_in_round(&reporter, Ed25519Keyring::Charlie, 3).is_err());
		assert_eq!(pallet_offences::Reports::<Runtime>::iter().count(), reports);

		assert_ok!(report_signed_in_round(&reporter, Ed25519Keyring::Bob, 3));
		assert_eq!(
			pallet_offences::Reports::<Runtime>::iter().count(),
			reports + 1
		);
	});
}

/// An offender already reported in the era still counts in a time slot it
/// shares with others: GRANDPA slashes a slot's offenders by how many there
/// are, and a refused report would leave it out of that count. With four
/// validators one offender is 56.25 %, two together are capped at 99 %.
#[test]
fn an_offender_on_file_still_counts_in_a_shared_slot() {
	use crate::staking::params::MAX_SLASH_FRACTION;
	use crate::test_utils::network::{report_in_round, report_signed_in_round, with_validators_of};
	let fraction = |who: &AccountId| {
		pallet_staking_async::ValidatorSlashInEra::<Runtime>::get(1, who).map(|(f, _)| f)
	};
	let solo = sp_runtime::Perbill::from_rational(9u32, 16);
	// A signed report of the solo offender joins the slot once another is in it.
	with_validators_of(4, || {
		let reporter = account(Sr25519Keyring::Ferdie);
		assert_ok!(report_signed_in_round(
			&reporter,
			Ed25519Keyring::Charlie,
			1
		));
		settle();
		assert_eq!(fraction(&charlie()), Some(solo));
		assert!(report_signed_in_round(&reporter, Ed25519Keyring::Charlie, 5).is_err());
		assert_ok!(report_signed_in_round(&reporter, Ed25519Keyring::Bob, 5));
		assert_ok!(report_signed_in_round(
			&reporter,
			Ed25519Keyring::Charlie,
			5
		));
		settle();
		assert_eq!(fraction(&charlie()), Some(MAX_SLASH_FRACTION));
		assert_eq!(
			fraction(&account(Sr25519Keyring::Bob)),
			Some(MAX_SLASH_FRACTION)
		);
	});
	// Both already on file: the block author's reports (a validator node's
	// unsigned ones) are heard, so the shared slot still escalates.
	with_validators_of(4, || {
		assert_ok!(report_in_round(Ed25519Keyring::Charlie, 1));
		assert_ok!(report_in_round(Ed25519Keyring::Bob, 2));
		settle();
		assert_ok!(report_in_round(Ed25519Keyring::Charlie, 5));
		assert_ok!(report_in_round(Ed25519Keyring::Bob, 5));
		settle();
		assert_eq!(fraction(&charlie()), Some(MAX_SLASH_FRACTION));
		assert_eq!(
			fraction(&account(Sr25519Keyring::Bob)),
			Some(MAX_SLASH_FRACTION)
		);
	});
}

/// An equivocation signed for a past era, reported later, slashes that era's
/// exposure too; reported for several eras, the slashes are capped together
/// at 99 %, so the offender keeps a sliver however many eras it is reported in.
/// Production parameters only: `fast-runtime` accepts offences of the active era
/// alone, so there is nothing to sum.
#[cfg(not(feature = "fast-runtime"))]
#[test]
fn reports_in_several_eras_slash_at_most_the_cap_together() {
	use crate::staking::params::MAX_SLASH_FRACTION;
	use crate::test_utils::network::equivocation_now;
	with_validators(|| {
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		let era_1 = equivocation_now(Ed25519Keyring::Charlie, 1);
		run_to_era(2);
		let era_2 = equivocation_now(Ed25519Keyring::Charlie, 2);
		let stake = <Staking as StakingInterface>::total_stake(&charlie()).unwrap();
		for (proof, key_owner) in [era_1, era_2] {
			assert_ok!(Grandpa::report_equivocation_unsigned(
				RuntimeOrigin::none(),
				Box::new(proof),
				key_owner
			));
		}
		settle();
		let slashed = crate::staking::offences::Slashed::get(charlie());
		assert_eq!(slashed.len(), 2);
		let total = slashed
			.iter()
			.fold(sp_runtime::Perbill::zero(), |sum, (_, f)| {
				sp_runtime::traits::Saturating::saturating_add(sum, *f)
			});
		assert_eq!(total, MAX_SLASH_FRACTION);

		run_to_era(2 + SLASH_DEFER_DURATION);
		settle();
		assert!(pallet_staking_async::UnappliedSlashes::<Runtime>::iter()
			.next()
			.is_none());
		let left = <Staking as StakingInterface>::total_stake(&charlie()).unwrap_or_default();
		assert!(left >= stake / 101, "{left} of {stake} left");
	});
}

/// An offence staking will not slash (era 0 has no exposures) is heard once,
/// for the ban; repeats are refused instead of being stored for good.
#[test]
fn an_offence_staking_drops_is_heard_once_for_the_ban() {
	use crate::test_utils::{
		blocks::run_block,
		network::{genesis, report_in_round},
	};
	genesis().execute_with(|| {
		run_block(1);
		assert_ok!(report_in_round(Ed25519Keyring::Charlie, 1));
		assert!(ValidatorSet::is_banned(&charlie()));
		let reports = pallet_offences::Reports::<Runtime>::iter().count();
		assert!(report_in_round(Ed25519Keyring::Charlie, 2).is_err());
		settle();
		assert!(report_in_round(Ed25519Keyring::Charlie, 3).is_err());
		assert_eq!(pallet_offences::Reports::<Runtime>::iter().count(), reports);
		assert!(crate::staking::offences::Slashed::get(charlie()).is_empty());
	});
}

/// A report checks out only for a real equivocation by the key it names, in
/// the set it names, with that key's own ownership proof.
#[test]
fn forged_equivocation_reports_are_refused() {
	use sp_consensus_grandpa::{Equivocation, EquivocationProof};
	with_validators(|| {
		let set_id = Grandpa::current_set_id();
		let owner = |key: Ed25519Keyring| {
			Historical::prove((KEY_TYPE, GrandpaId::unchecked_from(key.public().0))).unwrap()
		};
		let report = |proof, key| {
			Grandpa::report_equivocation_unsigned(RuntimeOrigin::none(), Box::new(proof), key)
		};
		let invalid_proof = || pallet_grandpa::Error::<Runtime>::InvalidEquivocationProof;
		// A prevote for `target` in round 1, signed by `signer`.
		let vote = |signer: Ed25519Keyring, target: u8| {
			let prevote = finality_grandpa::Prevote {
				target_hash: sp_core::H256::repeat_byte(target),
				target_number: 1,
			};
			let payload = sp_consensus_grandpa::localized_payload(
				1,
				set_id,
				&finality_grandpa::Message::Prevote(prevote.clone()),
			);
			(prevote, signer.sign(&payload).into())
		};
		let charlie_votes = |first, second| {
			EquivocationProof::new(
				set_id,
				Equivocation::Prevote(finality_grandpa::Equivocation {
					round_number: 1,
					identity: GrandpaId::unchecked_from(Ed25519Keyring::Charlie.public().0),
					first,
					second,
				}),
			)
		};

		// Bob's signatures under Charlie's key.
		let forged = charlie_votes(vote(Ed25519Keyring::Bob, 1), vote(Ed25519Keyring::Bob, 2));
		assert_noop!(
			report(forged, owner(Ed25519Keyring::Charlie)),
			invalid_proof()
		);

		// The same vote twice is no equivocation.
		let same = charlie_votes(
			vote(Ed25519Keyring::Charlie, 1),
			vote(Ed25519Keyring::Charlie, 1),
		);
		assert_noop!(
			report(same, owner(Ed25519Keyring::Charlie)),
			invalid_proof()
		);

		// Signed for another set.
		let other_set = prevote_equivocation(Ed25519Keyring::Charlie, set_id + 1);
		assert!(report(other_set, owner(Ed25519Keyring::Charlie)).is_err());

		// Alice's ownership proof for Charlie's equivocation.
		let real = prevote_equivocation(Ed25519Keyring::Charlie, set_id);
		assert_noop!(
			report(real, owner(Ed25519Keyring::Alice)),
			pallet_grandpa::Error::<Runtime>::InvalidKeyOwnershipProof
		);
		assert!(!ValidatorSet::is_banned(&charlie()));
		assert_eq!(pallet_offences::Reports::<Runtime>::iter().count(), 0);
	});
}

/// Only governance cancels a deferred slash; anyone may apply one that is due,
/// never one that is not yet due, and never twice.
#[test]
fn slashes_are_cancelled_by_governance_and_applied_only_when_due() {
	with_validators(|| {
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		assert_ok!(report_charlie());
		settle();
		let (who, fraction, page) = charlie_slash().expect("a deferred slash");
		let anyone = RuntimeOrigin::signed(account(Sr25519Keyring::Dave));
		assert_noop!(
			Staking::cancel_deferred_slash(
				anyone.clone(),
				APPLY_ERA,
				vec![(who.clone(), fraction)]
			),
			sp_runtime::DispatchError::BadOrigin
		);
		let key = (who, fraction, page);
		assert!(Staking::apply_slash(anyone.clone(), APPLY_ERA, key.clone()).is_err());
		assert!(charlie_slash().is_some(), "not due yet");

		run_to_era(APPLY_ERA);
		settle();
		assert!(charlie_slash().is_none(), "applied");
		let left = <Staking as StakingInterface>::total_stake(&charlie()).unwrap_or_default();
		assert!(Staking::apply_slash(anyone, APPLY_ERA, key).is_err());
		assert_eq!(
			<Staking as StakingInterface>::total_stake(&charlie()).unwrap_or_default(),
			left,
			"never twice"
		);
	});
}

/// Staking disables up to a third of the set, rounded down: with three
/// validators nobody (KL-40). The offender is still banned and chilled.
#[test]
fn a_set_of_three_disables_nobody() {
	with_validators(|| {
		assert_ok!(report_charlie());
		settle();
		assert!(pallet_session::DisabledValidators::<Runtime>::get().is_empty());
		assert!(ValidatorSet::is_banned(&charlie()));
	});
}
