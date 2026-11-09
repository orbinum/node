//! The admission rule and its three enforcement points (the candidacy extension, the
//! election filter and removal from the validator set), and the extension itself.

use super::{account, approve, bond, elected_candidates, offer, set_keys};
use crate::{
	staking::{
		admission::{check, Inadmissible, StakingCandidacy},
		candidacy::{check_candidacy, CheckValidatorCandidacy},
		params::*,
	},
	test_utils::with_ext,
	AccountId, Runtime, RuntimeCall, RuntimeOrigin, Staking, ValidatorSet,
};
use frame_support::assert_ok;
use pallet_staking_async::ValidatorPrefs;
use pallet_validator_set::{AdmissionMode, BanTerm, Candidacy};
use sp_runtime::{
	traits::{TransactionExtension, Zero},
	Perbill,
};

/// Every combination of the rule's inputs, in both modes: the extension's check,
/// the election filter and the rule itself must agree on every one, so a
/// candidacy the extension lets through is one the election can elect.
#[test]
fn admission_truth_table() {
	for mode in [AdmissionMode::Permissioned, AdmissionMode::Open] {
		with_ext(|| {
			pallet_staking_async::MinValidatorBond::<Runtime>::put(100);
			pallet_validator_set::Mode::<Runtime>::put(mode);
			let min = crate::staking::admission::min_self_bond(mode);

			let mut cases = Vec::new();
			for case in 0u8..32 {
				let (banned, keys, enough, offered, approved) = (
					case & 1 != 0,
					case & 2 != 0,
					case & 4 != 0,
					case & 8 != 0,
					case & 16 != 0,
				);
				let who = account(case + 1);
				if banned {
					pallet_validator_set::Bans::<Runtime>::insert(&who, BanTerm::Permanent);
				}
				if keys {
					set_keys(&who);
				}
				bond(&who, if enough { min } else { min - 1 });
				if offered {
					offer(&who);
				}
				if approved {
					approve(&who);
				}
				cases.push((who, banned, keys, enough, offered, approved));
			}

			let admission = ValidatorSet::admission();
			let elected = elected_candidates();
			for (who, banned, keys, enough, offered, approved) in cases {
				let expected =
					!banned && keys && enough && (approved || mode == AdmissionMode::Open);
				let rule = check(&admission, &who);
				assert_eq!(rule.is_ok(), expected, "{mode:?} {who:?}");
				assert_eq!(
					check_candidacy(&who, &ValidatorPrefs::default()).is_ok(),
					expected,
					"extension disagrees: {mode:?} {who:?}"
				);
				assert_eq!(
					elected.contains(&who),
					expected && offered,
					"election disagrees: {mode:?} {who:?}"
				);
				assert_eq!(
					<StakingCandidacy as Candidacy<AccountId>>::is_inadmissible_candidate(&who),
					offered && !expected,
					"chill_inadmissible disagrees: {mode:?} {who:?}"
				);
			}
		});
	}
}

#[test]
fn open_mode_floor_overrides_a_lower_min_bond() {
	with_ext(|| {
		pallet_staking_async::MinValidatorBond::<Runtime>::put(1);
		pallet_validator_set::Mode::<Runtime>::put(AdmissionMode::Open);
		let who = account(1);
		set_keys(&who);
		bond(&who, OPEN_MODE_MIN_SELF_BOND - 1);
		assert_eq!(
			check(&ValidatorSet::admission(), &who),
			Err(Inadmissible::InsufficientSelfBond)
		);
	});
}

#[test]
fn open_mode_requires_the_floor_first() {
	with_ext(|| {
		pallet_staking_async::MinValidatorBond::<Runtime>::put(OPEN_MODE_MIN_SELF_BOND - 1);
		assert!(
			ValidatorSet::set_admission_mode(RuntimeOrigin::root(), AdmissionMode::Open).is_err()
		);
		pallet_staking_async::MinValidatorBond::<Runtime>::put(OPEN_MODE_MIN_SELF_BOND);
		assert_ok!(ValidatorSet::set_admission_mode(
			RuntimeOrigin::root(),
			AdmissionMode::Open
		));
	});
}

#[test]
fn a_slash_below_the_minimum_drops_the_candidate() {
	with_ext(|| {
		let who = account(1);
		set_keys(&who);
		approve(&who);
		bond(&who, 1_000);
		offer(&who);
		pallet_staking_async::MinValidatorBond::<Runtime>::put(1_000);
		assert_eq!(elected_candidates(), vec![who.clone()]);

		// What a slash leaves behind: less active stake than the minimum.
		pallet_staking_async::MinValidatorBond::<Runtime>::put(1_001);
		assert!(elected_candidates().is_empty());
	});
}

fn prefs(commission: Perbill) -> ValidatorPrefs {
	ValidatorPrefs {
		commission,
		blocked: false,
	}
}

/// With no ceiling set (staking's default, 100 %), any commission is a candidacy.
#[test]
fn no_commission_ceiling_by_default() {
	with_ext(|| {
		let who = account(1);
		set_keys(&who);
		approve(&who);
		bond(&who, 1_000);
		assert_eq!(
			pallet_staking_async::MaxCommission::<Runtime>::get(),
			Perbill::one()
		);
		assert_eq!(check_candidacy(&who, &prefs(Perbill::one())), Ok(()));
		pallet_staking_async::Validators::<Runtime>::insert(&who, prefs(Perbill::one()));
		assert_eq!(elected_candidates(), vec![who]);
	});
}

/// A candidacy above the on-chain ceiling is refused, and one stored above it
/// (a ceiling lowered since, or root's `sudo_as`) is not electable.
#[test]
fn a_commission_above_the_ceiling_is_not_electable() {
	with_ext(|| {
		let ceiling = Perbill::from_percent(10);
		pallet_staking_async::MaxCommission::<Runtime>::put(ceiling);
		let who = account(1);
		set_keys(&who);
		approve(&who);
		bond(&who, 1_000);
		pallet_staking_async::MinValidatorBond::<Runtime>::put(1_000);
		pallet_staking_async::Validators::<Runtime>::insert(&who, prefs(ceiling));
		assert_eq!(elected_candidates(), vec![who.clone()]);

		let above = Perbill::from_parts(ceiling.deconstruct() + 1);
		pallet_staking_async::Validators::<Runtime>::insert(&who, prefs(above));
		assert!(elected_candidates().is_empty());
		assert_eq!(
			check_candidacy(&who, &prefs(above)),
			Err(Inadmissible::CommissionTooHigh)
		);
		// Lowering it is a candidacy like any other.
		assert_eq!(check_candidacy(&who, &prefs(ceiling)), Ok(()));
	});
}

#[test]
fn not_bonded_is_its_own_reason() {
	with_ext(|| {
		let who = account(1);
		set_keys(&who);
		approve(&who);
		assert_eq!(
			check(&ValidatorSet::admission(), &who),
			Err(Inadmissible::NotBonded)
		);
	});
}

#[test]
fn removing_or_banning_chills() {
	with_ext(|| {
		let (a, b) = (account(1), account(2));
		for who in [&a, &b] {
			set_keys(who);
			approve(who);
			bond(who, 1_000);
			assert_ok!(Staking::validate(
				RuntimeOrigin::signed(who.clone()),
				ValidatorPrefs::default()
			));
		}

		assert_ok!(ValidatorSet::remove_validator(
			RuntimeOrigin::root(),
			a.clone()
		));
		assert!(!pallet_staking_async::Validators::<Runtime>::contains_key(
			&a
		));

		assert_ok!(ValidatorSet::ban_validator(
			RuntimeOrigin::root(),
			b.clone(),
			BanTerm::Permanent
		));
		assert!(!pallet_staking_async::Validators::<Runtime>::contains_key(
			&b
		));
	});
}

fn validate_call(commission: Perbill) -> RuntimeCall {
	RuntimeCall::Staking(pallet_staking_async::Call::validate {
		prefs: prefs(commission),
	})
}

pub(super) fn submit(who: &AccountId, call: &RuntimeCall) -> Result<(), u8> {
	use sp_runtime::{
		traits::TxBaseImplication,
		transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidityError},
	};
	CheckValidatorCandidacy
		.validate(
			RuntimeOrigin::signed(who.clone()),
			call,
			&Default::default(),
			0,
			(),
			&TxBaseImplication(()),
			TransactionSource::External,
		)
		.map(|_| ())
		.map_err(|e| match e {
			TransactionValidityError::Invalid(InvalidTransaction::Custom(code)) => code,
			other => panic!("unexpected rejection {other:?}"),
		})
}

#[test]
fn extension_rejects_with_stable_codes() {
	with_ext(|| {
		pallet_staking_async::MinValidatorBond::<Runtime>::put(1_000);
		let who = account(1);
		let ok = validate_call(Perbill::from_percent(5));

		assert_eq!(submit(&who, &ok), Err(Inadmissible::NotBonded as u8));
		bond(&who, 1_000);
		assert_eq!(submit(&who, &ok), Err(Inadmissible::NotApproved as u8));
		approve(&who);
		assert_eq!(submit(&who, &ok), Err(Inadmissible::NoSessionKeys as u8));
		set_keys(&who);
		assert_eq!(submit(&who, &ok), Ok(()));

		assert_eq!(submit(&who, &validate_call(Perbill::one())), Ok(()));
		assert_ok!(Staking::set_max_commission(
			RuntimeOrigin::root(),
			Perbill::from_percent(20)
		));
		assert_eq!(
			submit(&who, &validate_call(Perbill::from_percent(21))),
			Err(Inadmissible::CommissionTooHigh as u8)
		);
		assert_eq!(
			submit(&who, &validate_call(Perbill::from_percent(20))),
			Ok(())
		);

		pallet_staking_async::MinValidatorBond::<Runtime>::put(1_001);
		assert_eq!(
			submit(&who, &ok),
			Err(Inadmissible::InsufficientSelfBond as u8)
		);

		pallet_validator_set::Bans::<Runtime>::insert(&who, BanTerm::Permanent);
		assert_eq!(submit(&who, &ok), Err(Inadmissible::Banned as u8));
	});
	assert_eq!(
		[1, 2, 3, 4, 5, 6, 7],
		[
			Inadmissible::NotApproved as u8,
			Inadmissible::Banned as u8,
			Inadmissible::NoSessionKeys as u8,
			Inadmissible::InsufficientSelfBond as u8,
			Inadmissible::CommissionTooHigh as u8,
			Inadmissible::NotBonded as u8,
			Inadmissible::TooManyCandidates as u8,
		]
	);
}

/// The election reads `MaxTargets` candidates and staking cuts the rest in
/// storage order: once that many offer themselves, a new candidacy is refused
/// whatever `MaxValidatorsCount` says, while a candidate may still update its
/// prefs.
#[test]
fn candidates_never_outnumber_what_the_election_reads() {
	with_ext(|| {
		pallet_staking_async::MinValidatorBond::<Runtime>::put(1_000);
		// As governance may set it with `staking.set_staking_configs`.
		pallet_staking_async::MaxValidatorsCount::<Runtime>::put(10 * MAX_VALIDATOR_CANDIDATES);
		let admissible = |n: u8| {
			let who = account(n);
			bond(&who, 1_000);
			approve(&who);
			set_keys(&who);
			who
		};
		let (newcomer, candidate) = (admissible(1), admissible(2));
		offer(&candidate);
		for i in 1..MAX_VALIDATOR_CANDIDATES - 1 {
			let mut raw = [0xaa; 32];
			raw[..4].copy_from_slice(&i.to_le_bytes());
			offer(&AccountId::from(raw));
		}
		let ok = validate_call(Perbill::from_percent(5));
		assert_eq!(submit(&newcomer, &ok), Ok(()), "one seat left");

		offer(&AccountId::from([0xbb; 32]));
		assert_eq!(
			pallet_staking_async::Validators::<Runtime>::count(),
			MAX_VALIDATOR_CANDIDATES
		);
		assert_eq!(
			submit(&newcomer, &ok),
			Err(Inadmissible::TooManyCandidates as u8)
		);
		assert_eq!(
			submit(&candidate, &ok),
			Ok(()),
			"a candidate updates its prefs"
		);

		assert_ok!(Staking::chill(RuntimeOrigin::signed(candidate)));
		assert_eq!(submit(&newcomer, &ok), Ok(()));
	});
}

#[test]
fn extension_ignores_other_calls_and_costs_nothing_for_them() {
	with_ext(|| {
		let remark = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
		assert_eq!(submit(&account(1), &remark), Ok(()));
		assert!(CheckValidatorCandidacy.weight(&remark).is_zero());
		assert!(!CheckValidatorCandidacy
			.weight(&validate_call(Perbill::zero()))
			.is_zero());
	});
}

/// Appending the extension must not change a single byte clients sign or send.
#[test]
fn extension_encodes_to_nothing() {
	use scale_codec::Encode;
	use scale_info::{TypeDef, TypeInfo};
	assert!(CheckValidatorCandidacy.encode().is_empty());
	match CheckValidatorCandidacy::type_info().type_def {
		TypeDef::Composite(c) => assert!(c.fields.is_empty()),
		other => panic!("unexpected type {other:?}"),
	}
	assert_eq!(
		<CheckValidatorCandidacy as TransactionExtension<RuntimeCall>>::IDENTIFIER,
		"CheckValidatorCandidacy"
	);
}

/// The extension only inspects the outer call. A pallet that wraps calls would
/// let a nested `staking.validate` past it; adding one must extend the extension
/// (the election filter still covers it meanwhile).
#[test]
fn no_call_wrapping_pallets() {
	use frame_support::traits::PalletsInfoAccess;
	let names: Vec<_> = crate::AllPalletsWithSystem::infos()
		.into_iter()
		.map(|p| p.name)
		.collect();
	for wrapper in ["Utility", "Proxy", "Multisig", "Recovery", "Scheduler"] {
		assert!(
			!names.contains(&wrapper),
			"{wrapper} wraps calls: extend CheckValidatorCandidacy to inspect nested calls"
		);
	}
}

/// The clamp and the snapshot filter read at most `MaxTargets` candidates,
/// however many root's `sudo_as` (with `MaxValidatorsCount` lifted) put in
/// `Validators`: both run in the session report, as mandatory weight.
#[test]
fn clamp_and_filter_are_bounded() {
	use crate::staking::commission::clamp_to_ceiling;
	use frame_support::dispatch::DispatchClass;
	with_ext(|| {
		let db = <Runtime as frame_system::Config>::DbWeight::get();
		let bound = MAX_VALIDATOR_CANDIDATES;
		let over = 10u32;
		// Inadmissible candidates (not bonded) above the ceiling.
		for i in 0..bound + over {
			let mut raw = [0xcc; 32];
			raw[..4].copy_from_slice(&i.to_le_bytes());
			pallet_staking_async::Validators::<Runtime>::insert(
				AccountId::from(raw),
				prefs(Perbill::from_percent(50)),
			);
		}
		let ceiling = Perbill::from_percent(10);
		pallet_staking_async::MaxCommission::<Runtime>::put(ceiling);

		let mandatory = || {
			frame_system::Pallet::<Runtime>::block_weight()
				.get(DispatchClass::Mandatory)
				.ref_time()
		};
		let before = mandatory();
		assert!(elected_candidates().is_empty());
		// The snapshot's own reads, then six per candidate read.
		assert_eq!(
			mandatory() - before,
			db.reads(5 + 6 * u64::from(bound)).ref_time()
		);

		let bound = u64::from(bound);
		assert_eq!(
			clamp_to_ceiling(),
			db.reads_writes(bound + 2 + bound, bound)
		);
		let clamped = pallet_staking_async::Validators::<Runtime>::iter_values()
			.filter(|p| p.commission == ceiling)
			.count();
		assert_eq!(clamped as u64, bound);
	});
}

/// A signed `staking.validate` from an account the rule rejects fails in
/// `apply_extrinsic` with the candidacy code, before it is charged or dispatched.
#[test]
fn apply_extrinsic_rejects_inadmissible_validate() {
	use crate::{
		signature::OrbinumSignature,
		test_utils::{signed_extra, with_dev_chain},
		Executive, SignedPayload, UncheckedExtrinsic,
	};
	use frame_support::traits::fungible::Inspect;
	use scale_codec::Encode;
	use sp_core::Pair;
	use sp_runtime::transaction_validity::InvalidTransaction;
	with_dev_chain(|| {
		let key = sp_keyring::Sr25519Keyring::Dave;
		let who = crate::test_utils::account(key);
		bond(&who, TEST_MIN_VALIDATOR_BOND);
		set_keys(&who);
		let call = validate_call(Perbill::zero());
		let extra = signed_extra(0, 0);
		let signature = SignedPayload::new(call.clone(), extra.clone())
			.unwrap()
			.using_encoded(|payload| key.pair().sign(payload));
		let xt = UncheckedExtrinsic::new_signed(
			call,
			who.clone(),
			OrbinumSignature::Sr25519(signature),
			extra,
		);
		let balance = crate::Balances::total_balance(&who);

		assert_eq!(
			Executive::apply_extrinsic(xt),
			Err(InvalidTransaction::Custom(Inadmissible::NotApproved as u8).into())
		);
		assert!(!pallet_staking_async::Validators::<Runtime>::contains_key(
			&who
		));
		assert_eq!(crate::Balances::total_balance(&who), balance, "no fee");
		assert_eq!(frame_system::Pallet::<Runtime>::account_nonce(&who), 0);
	});
}

/// Root's `sudo_as` skips the extension: a bonded, keyed account outside the
/// allowlist becomes a candidate, staked to win a seat, yet the election
/// filter keeps it out of the session. Benchmark builds wire the unfiltered list.
#[cfg(not(feature = "runtime-benchmarks"))]
#[test]
fn sudo_as_validate_never_reaches_the_session() {
	use crate::{
		test_utils::{blocks::run_to_era, network::with_validators},
		Session,
	};
	use sp_runtime::traits::Dispatchable;
	with_validators(|| {
		let key = sp_keyring::Sr25519Keyring::Dave;
		let who = crate::test_utils::account(key);
		bond(&who, 10 * TEST_MIN_VALIDATOR_BOND);
		assert_ok!(<Session as pallet_session::SessionInterface>::set_keys(
			&who,
			crate::opaque::SessionKeys {
				aura: sp_core::sr25519::Public::from_raw(key.public().0).into(),
				grandpa: sp_core::ed25519::Public::from_raw(key.public().0).into(),
			}
		));
		let sudo = pallet_sudo::Key::<Runtime>::get().expect("a sudo key");
		let call = RuntimeCall::Sudo(pallet_sudo::Call::sudo_as {
			who: who.clone().into(),
			call: Box::new(validate_call(Perbill::zero())),
		});
		assert_ok!(call.dispatch(RuntimeOrigin::signed(sudo)));
		assert!(pallet_staking_async::Validators::<Runtime>::contains_key(
			&who
		));
		assert_eq!(
			check(&ValidatorSet::admission(), &who),
			Err(Inadmissible::NotApproved)
		);

		let era = crate::test_utils::blocks::active_era();
		run_to_era(era + 2);
		assert!(!Session::validators().contains(&who));
		assert_eq!(Session::validators().len(), 3);
	});
}

#[test]
fn deregistering_chills_the_candidacy() {
	with_ext(|| {
		let who = account(1);
		set_keys(&who);
		approve(&who);
		bond(&who, 1_000);
		assert_ok!(Staking::validate(
			RuntimeOrigin::signed(who.clone()),
			ValidatorPrefs::default()
		));
		assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
			who.clone()
		)));
		assert!(!pallet_staking_async::Validators::<Runtime>::contains_key(
			&who
		));
	});
}

/// A ban that ends, or a lifted one, or a removed account added back, makes the
/// account admissible again but not a candidate: its candidacy was chilled, and
/// it must call `staking.validate` again.
#[test]
fn readmission_needs_validate_again() {
	with_ext(|| {
		type Readmit = fn(&AccountId);
		let readmit: [(&str, Readmit); 3] = [
			("expired ban", |who| {
				let now = frame_system::Pallet::<Runtime>::block_number();
				assert_ok!(ValidatorSet::ban_validator(
					RuntimeOrigin::root(),
					who.clone(),
					BanTerm::Until(now + 10)
				));
				frame_system::Pallet::<Runtime>::set_block_number(now + 10);
			}),
			("unban", |who| {
				assert_ok!(ValidatorSet::ban_validator(
					RuntimeOrigin::root(),
					who.clone(),
					BanTerm::Permanent
				));
				assert_ok!(ValidatorSet::unban_validator(
					RuntimeOrigin::root(),
					who.clone()
				));
			}),
			("removed and added back", |who| {
				assert_ok!(ValidatorSet::remove_validator(
					RuntimeOrigin::root(),
					who.clone()
				));
				assert_ok!(ValidatorSet::add_validator(
					RuntimeOrigin::root(),
					who.clone()
				));
			}),
		];
		for (n, (case, readmit)) in readmit.into_iter().enumerate() {
			let who = account(n as u8 + 1);
			set_keys(&who);
			approve(&who);
			bond(&who, 1_000);
			assert_ok!(Staking::validate(
				RuntimeOrigin::signed(who.clone()),
				ValidatorPrefs::default()
			));
			assert!(elected_candidates().contains(&who), "{case}");

			readmit(&who);
			assert_eq!(check(&ValidatorSet::admission(), &who), Ok(()), "{case}");
			assert!(!elected_candidates().contains(&who), "{case}");

			assert_eq!(
				check_candidacy(&who, &ValidatorPrefs::default()),
				Ok(()),
				"{case}"
			);
			assert_ok!(Staking::validate(
				RuntimeOrigin::signed(who.clone()),
				ValidatorPrefs::default()
			));
			assert!(elected_candidates().contains(&who), "{case}");
		}
	});
}

/// Candidates the rule no longer admits keep their slot until anyone ends them:
/// purged keys, a return to `Permissioned`, a commission above a lowered
/// ceiling. An admissible candidate cannot be ended by others.
#[test]
fn anyone_frees_the_slot_of_an_inadmissible_candidate() {
	with_ext(|| {
		pallet_staking_async::MinValidatorBond::<Runtime>::put(100);
		pallet_staking_async::MaxCommission::<Runtime>::put(Perbill::from_percent(20));
		let [keyless, unapproved, expensive, fine] = [1, 2, 3, 4].map(account);
		for who in [&keyless, &unapproved, &expensive, &fine] {
			set_keys(who);
			bond(who, OPEN_MODE_MIN_SELF_BOND);
			offer(who);
		}
		for who in [&keyless, &expensive, &fine] {
			approve(who);
		}
		pallet_session::NextKeys::<Runtime>::remove(&keyless);
		pallet_staking_async::Validators::<Runtime>::insert(
			&expensive,
			ValidatorPrefs {
				commission: Perbill::one(),
				blocked: false,
			},
		);
		let anyone = RuntimeOrigin::signed(account(9));
		// Above a lowered ceiling: clamped at the next session report, not ended.
		for who in [&fine, &expensive] {
			assert_eq!(
				ValidatorSet::chill_inadmissible(anyone.clone(), who.clone()),
				Err(pallet_validator_set::Error::<Runtime>::CandidacyAdmissible.into())
			);
		}
		for who in [&keyless, &unapproved] {
			assert_ok!(ValidatorSet::chill_inadmissible(
				anyone.clone(),
				who.clone()
			));
			assert!(!pallet_staking_async::Validators::<Runtime>::contains_key(
				who
			));
		}
		assert_eq!(pallet_staking_async::Validators::<Runtime>::count(), 2);
	});
}

/// With every candidate slot taken, ending one inadmissible candidacy lets an
/// admissible newcomer in.
#[test]
fn a_freed_slot_admits_a_new_candidate() {
	with_ext(|| {
		pallet_staking_async::MinValidatorBond::<Runtime>::put(100);
		let max = <Runtime as pallet_paged_election::Config>::MaxTargets::get();
		for n in 0..max {
			let mut raw = [7u8; 32];
			raw[..4].copy_from_slice(&n.to_le_bytes());
			let who = AccountId::from(raw);
			bond(&who, 100);
			offer(&who);
		}
		let newcomer = account(1);
		set_keys(&newcomer);
		bond(&newcomer, 100);
		approve(&newcomer);
		let prefs = ValidatorPrefs::default();
		assert_eq!(
			check_candidacy(&newcomer, &prefs),
			Err(Inadmissible::TooManyCandidates)
		);
		let mut raw = [7u8; 32];
		raw[..4].copy_from_slice(&0u32.to_le_bytes());
		assert_ok!(ValidatorSet::chill_inadmissible(
			RuntimeOrigin::signed(newcomer.clone()),
			AccountId::from(raw)
		));
		assert_ok!(check_candidacy(&newcomer, &prefs));
	});
}

/// Losing the right to validate ends a candidacy, not a nomination: an
/// allowlisted account that nominates keeps nominating when it is removed or
/// banned.
#[test]
fn removing_an_allowlisted_nominator_keeps_its_nominations() {
	with_ext(|| {
		let (nominator, validator) = (account(1), account(2));
		bond(&validator, 1_000);
		offer(&validator);
		approve(&nominator);
		bond(&nominator, 1_000);
		pallet_staking_async::MinNominatorBond::<Runtime>::put(1);
		assert_ok!(<Staking as sp_staking::StakingInterface>::nominate(
			&nominator,
			vec![validator]
		));
		assert_ok!(ValidatorSet::remove_validator(
			RuntimeOrigin::root(),
			nominator.clone()
		));
		assert_ok!(ValidatorSet::ban_validator(
			RuntimeOrigin::root(),
			nominator.clone(),
			BanTerm::Permanent
		));
		assert!(pallet_staking_async::Nominators::<Runtime>::contains_key(
			&nominator
		));
	});
}
