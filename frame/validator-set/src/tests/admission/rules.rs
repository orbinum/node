//! Admission: the mode, the allowlist, session keys and bans, in both modes.

use crate::tests::*;
use crate::{
	AdmissionMode, BanTerm, Bans, Inadmissible, LastAuthorVersion, Mode, NodeVersion, Pallet,
};
use frame_support::traits::Contains;

fn check(who: AccountId) -> Result<(), Inadmissible> {
	Pallet::<Test>::admission().check(&who)
}

fn open() {
	assert_ok!(ValidatorSet::set_admission_mode(
		RuntimeOrigin::root(),
		AdmissionMode::Open
	));
}

// ── Mode ─────────────────────────────────────────────────────────────────────

#[test]
fn admission_defaults_to_permissioned() {
	ExtBuilder::default().build().execute_with(|| {
		assert_eq!(Mode::<Test>::get(), AdmissionMode::Permissioned);
		assert_eq!(
			Pallet::<Test>::admission().mode(),
			AdmissionMode::Permissioned
		);
	});
}

#[test]
fn set_admission_mode_requires_origin() {
	ExtBuilder::default().build().execute_with(|| {
		assert_noop!(
			ValidatorSet::set_admission_mode(RuntimeOrigin::signed(1), AdmissionMode::Open),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn set_admission_mode_emits_event() {
	ExtBuilder::default().build().execute_with(|| {
		open();
		System::assert_last_event(
			Event::AdmissionModeSet {
				mode: AdmissionMode::Open,
			}
			.into(),
		);
	});
}

#[test]
fn open_blocked_by_guard() {
	ExtBuilder::default().build().execute_with(|| {
		set_open_mode_allowed(false);
		assert_noop!(
			ValidatorSet::set_admission_mode(RuntimeOrigin::root(), AdmissionMode::Open),
			Error::<Test>::OpenModeGuardFailed
		);
	});
}

#[test]
fn back_to_permissioned_always_allowed() {
	ExtBuilder::default().build().execute_with(|| {
		open();
		set_open_mode_allowed(false);
		assert_ok!(ValidatorSet::set_admission_mode(
			RuntimeOrigin::root(),
			AdmissionMode::Permissioned
		));
		assert_eq!(Mode::<Test>::get(), AdmissionMode::Permissioned);
	});
}

#[test]
fn permissioned_requires_allowlist() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_eq!(check(1), Ok(()));
			assert_eq!(check(42), Err(Inadmissible::NotApproved));
		});
}

#[test]
fn open_ignores_allowlist() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			open();
			assert_eq!(check(1), Ok(()));
			assert_eq!(check(42), Ok(()));
		});
}

#[test]
fn both_modes_require_session_keys() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			set_mock_session_keys(false);
			assert_eq!(check(1), Err(Inadmissible::NoSessionKeys));
			open();
			assert_eq!(check(42), Err(Inadmissible::NoSessionKeys));
		});
}

#[test]
fn contains_agrees_with_check() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert!(<ValidatorSet as Contains<u64>>::contains(&1));
			assert!(!<ValidatorSet as Contains<u64>>::contains(&42));
		});
}

#[test]
fn removed_validator_drops_from_admission() {
	ExtBuilder::default()
		.validators(vec![1, 2])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 1));
			assert_eq!(check(1), Err(Inadmissible::NotApproved));
		});
}

// ── Bans ─────────────────────────────────────────────────────────────────────

#[test]
fn ban_requires_origin() {
	ExtBuilder::default().build().execute_with(|| {
		assert_noop!(
			ValidatorSet::ban_validator(RuntimeOrigin::signed(1), 2, BanTerm::Permanent),
			sp_runtime::DispatchError::BadOrigin
		);
		assert_noop!(
			ValidatorSet::unban_validator(RuntimeOrigin::signed(1), 2),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn banned_not_admitted_in_either_mode() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::ban_validator(
				RuntimeOrigin::root(),
				1,
				BanTerm::Permanent
			));
			assert_eq!(check(1), Err(Inadmissible::Banned));
			open();
			assert_eq!(check(1), Err(Inadmissible::Banned));
		});
}

#[test]
fn ban_emits_event_and_fires_removal_hook() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::ban_validator(
				RuntimeOrigin::root(),
				1,
				BanTerm::Until(10)
			));
			assert_eq!(removed_hook_calls(), vec![1]);
			System::assert_last_event(
				Event::ValidatorBanned {
					validator: 1,
					term: BanTerm::Until(10),
				}
				.into(),
			);
		});
}

#[test]
fn ban_keeps_allowlist_entry() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::ban_validator(
				RuntimeOrigin::root(),
				1,
				BanTerm::Permanent
			));
			assert!(ApprovedValidators::<Test>::get().contains(&1));
		});
}

#[test]
fn ban_expires_lazily_at_until() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::ban_validator(
				RuntimeOrigin::root(),
				1,
				BanTerm::Until(5)
			));
			System::set_block_number(4);
			assert_eq!(check(1), Err(Inadmissible::Banned));
			System::set_block_number(5);
			assert_eq!(check(1), Ok(()));
			// Inert, not deleted.
			assert!(Bans::<Test>::contains_key(1));
		});
}

#[test]
fn permanent_ban_never_expires() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::ban_validator(
				RuntimeOrigin::root(),
				1,
				BanTerm::Permanent
			));
			System::set_block_number(u64::MAX);
			assert_eq!(check(1), Err(Inadmissible::Banned));
		});
}

#[test]
fn ban_rejects_a_term_already_over() {
	ExtBuilder::default().build().execute_with(|| {
		System::set_block_number(5);
		assert_noop!(
			ValidatorSet::ban_validator(RuntimeOrigin::root(), 1, BanTerm::Until(5)),
			Error::<Test>::BanAlreadyExpired
		);
	});
}

#[test]
fn governance_ban_replaces_the_term() {
	ExtBuilder::default().build().execute_with(|| {
		assert_ok!(ValidatorSet::ban_validator(
			RuntimeOrigin::root(),
			1,
			BanTerm::Permanent
		));
		assert_ok!(ValidatorSet::ban_validator(
			RuntimeOrigin::root(),
			1,
			BanTerm::Until(10)
		));
		assert_eq!(Bans::<Test>::get(1), Some(BanTerm::Until(10)));
	});
}

#[test]
fn offence_ban_never_shortens() {
	ExtBuilder::default().build().execute_with(|| {
		Pallet::<Test>::ban_offender(&1, BanTerm::Until(20));
		Pallet::<Test>::ban_offender(&1, BanTerm::Until(10));
		assert_eq!(Bans::<Test>::get(1), Some(BanTerm::Until(20)));

		Pallet::<Test>::ban_offender(&1, BanTerm::Until(30));
		assert_eq!(Bans::<Test>::get(1), Some(BanTerm::Until(30)));

		Pallet::<Test>::ban_offender(&1, BanTerm::Permanent);
		Pallet::<Test>::ban_offender(&1, BanTerm::Until(40));
		assert_eq!(Bans::<Test>::get(1), Some(BanTerm::Permanent));

		assert_ok!(ValidatorSet::ban_validator(
			RuntimeOrigin::root(),
			2,
			BanTerm::Permanent
		));
		Pallet::<Test>::ban_offender(&2, BanTerm::Until(30));
		assert_eq!(Bans::<Test>::get(2), Some(BanTerm::Permanent));
	});
}

#[test]
fn an_offence_ban_already_over_changes_nothing() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			System::set_block_number(50);
			Pallet::<Test>::ban_offender(&1, BanTerm::Until(40));
			assert_eq!(Bans::<Test>::get(1), None);
			assert!(removed_hook_calls().is_empty(), "nothing to stop");
			assert_eq!(check(1), Ok(()));
		});
}

#[test]
fn a_ban_drops_the_declared_version() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			// A banned validator must not count toward a version quorum.
			LastAuthorVersion::<Test>::insert(1, (NodeVersion::new(1, 0, 0), 1));
			Pallet::<Test>::ban_offender(&1, BanTerm::Until(30));
			assert!(LastAuthorVersion::<Test>::get(1).is_none());
			assert_ok!(ValidatorSet::do_try_state());
		});
}

#[test]
fn unban_restores_admission() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::ban_validator(
				RuntimeOrigin::root(),
				1,
				BanTerm::Permanent
			));
			assert_ok!(ValidatorSet::unban_validator(RuntimeOrigin::root(), 1));
			assert_eq!(check(1), Ok(()));
			System::assert_last_event(Event::ValidatorUnbanned { validator: 1 }.into());
		});
}

#[test]
fn unban_requires_a_ban() {
	ExtBuilder::default().build().execute_with(|| {
		assert_noop!(
			ValidatorSet::unban_validator(RuntimeOrigin::root(), 1),
			Error::<Test>::NotBanned
		);
	});
}

#[test]
fn add_validator_rejects_banned() {
	ExtBuilder::default()
		.validators(vec![])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::ban_validator(
				RuntimeOrigin::root(),
				42,
				BanTerm::Until(10)
			));
			assert_noop!(
				ValidatorSet::add_validator(RuntimeOrigin::root(), 42),
				Error::<Test>::Banned
			);
			System::set_block_number(10);
			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 42));
		});
}

#[test]
fn ban_term_longest() {
	use BanTerm::*;
	assert_eq!(Until(3u64).longest(Until(5)), Until(5));
	assert_eq!(Until(5u64).longest(Until(3)), Until(5));
	assert_eq!(Until(5u64).longest(Permanent), Permanent);
	assert_eq!(Permanent.longest(Until(5u64)), Permanent);
}

// ── Author-version quorum over the active set ───────────────────────────────

#[test]
fn quorum_counts_active_not_approved() {
	ExtBuilder::default()
		.validators(vec![1, 2, 3])
		.build()
		.execute_with(|| {
			let v = NodeVersion::new(1, 0, 0);
			let now = System::block_number();
			// Only 1 and 2 were elected; 3 is approved but cannot author.
			set_active_validators(Some(vec![1, 2]));
			LastAuthorVersion::<Test>::insert(1, (v, now));
			LastAuthorVersion::<Test>::insert(2, (v, now));
			assert_ok!(ValidatorSet::set_min_author_version(
				RuntimeOrigin::root(),
				Some(v)
			));
		});
}

/// A live chain reaches version 1 through the runtime's staking migration.
#[test]
fn storage_version_is_one() {
	use frame_support::traits::{GetStorageVersion, StorageVersion};
	assert_eq!(
		Pallet::<Test>::in_code_storage_version(),
		StorageVersion::new(1)
	);
}

// ── Inadmissible candidacies ─────────────────────────────────────────────────

#[test]
fn anyone_ends_an_inadmissible_candidacy() {
	ExtBuilder::default().build().execute_with(|| {
		set_inadmissible_candidate(5);
		assert_ok!(ValidatorSet::chill_inadmissible(
			RuntimeOrigin::signed(9),
			5
		));
		assert_eq!(removed_hook_calls(), vec![5]);
		System::assert_last_event(Event::CandidacyEnded { validator: 5 }.into());
	});
}

#[test]
fn an_admissible_candidacy_cannot_be_ended() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::chill_inadmissible(RuntimeOrigin::signed(9), 1),
				Error::<Test>::CandidacyAdmissible
			);
			assert!(removed_hook_calls().is_empty());
		});
}

#[test]
fn ending_a_candidacy_needs_a_signed_origin() {
	ExtBuilder::default().build().execute_with(|| {
		set_inadmissible_candidate(5);
		assert_noop!(
			ValidatorSet::chill_inadmissible(RuntimeOrigin::none(), 5),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}
