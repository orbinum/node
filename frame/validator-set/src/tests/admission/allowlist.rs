//! The allowlist: genesis, adding, removing, leaving and the removal hook.

use crate::tests::*;
use crate::{LastAuthorVersion, NodeVersion};

// ── Genesis ──────────────────────────────────────────────────────────────────

#[test]
fn genesis_populates_approved_validators() {
	ExtBuilder::default()
		.validators(vec![10, 20, 30])
		.build()
		.execute_with(|| {
			let approved = ApprovedValidators::<Test>::get();
			assert_eq!(approved.as_slice(), &[10u64, 20, 30]);
		});
}

#[test]
fn genesis_does_not_apply_the_session_key_gate() {
	// Deliberate: this pallet's genesis runs before pallet-session's, so NextKeys
	// is still empty and the gate would reject every account. Chain-spec authors
	// seed both from the same list. Pinned here so the behaviour is a decision,
	// not an accident.
	ExtBuilder::default()
		.validators(vec![10, 20])
		.build()
		.execute_with(|| {
			set_mock_session_keys(false);
			assert_eq!(ApprovedValidators::<Test>::get().as_slice(), &[10u64, 20]);
		});
}

#[test]
fn genesis_empty_validator_set_is_allowed() {
	ExtBuilder::default()
		.validators(vec![])
		.build()
		.execute_with(|| {
			assert!(ApprovedValidators::<Test>::get().is_empty());
		});
}

// ── add_validator (sudo) ──────────────────────────────────────────────────────

#[test]
fn add_validator_inserts_account() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 42));
			assert!(ApprovedValidators::<Test>::get().contains(&42));
		});
}

#[test]
fn add_validator_emits_event() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 99));
			System::assert_last_event(Event::ValidatorAdded { validator: 99 }.into());
		});
}

#[test]
fn add_validator_fails_if_already_present() {
	ExtBuilder::default()
		.validators(vec![1, 2])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::add_validator(RuntimeOrigin::root(), 1),
				Error::<Test>::AlreadyValidator
			);
		});
}

#[test]
fn add_validator_fails_when_set_is_full() {
	// MaxValidators = 10; fill it up first
	let full: Vec<u64> = (1..=10).collect();
	ExtBuilder::default()
		.validators(full)
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::add_validator(RuntimeOrigin::root(), 99),
				Error::<Test>::TooManyValidators
			);
		});
}

#[test]
fn add_validator_requires_root() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::add_validator(RuntimeOrigin::signed(1), 42),
				sp_runtime::traits::BadOrigin
			);
		});
}

#[test]
fn add_validator_fails_without_session_keys() {
	// An account with no session keys would hold a slot without authoring blocks.
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			set_mock_session_keys(false);
			assert_noop!(
				ValidatorSet::add_validator(RuntimeOrigin::root(), 42),
				Error::<Test>::NoSessionKeys
			);
			assert!(!ApprovedValidators::<Test>::get().contains(&42));
		});
}

#[test]
fn add_validator_works_once_session_keys_are_registered() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			set_mock_session_keys(false);
			assert_noop!(
				ValidatorSet::add_validator(RuntimeOrigin::root(), 42),
				Error::<Test>::NoSessionKeys
			);

			set_mock_session_keys(true);
			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 42));
			assert!(ApprovedValidators::<Test>::get().contains(&42));
		});
}

// ── remove_validator (sudo) ───────────────────────────────────────────────────

#[test]
fn remove_validator_deletes_account_from_approved() {
	ExtBuilder::default()
		.validators(vec![1, 2, 3])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 2));
			let approved = ApprovedValidators::<Test>::get();
			assert!(!approved.contains(&2));
			assert!(approved.contains(&1));
			assert!(approved.contains(&3));
		});
}

#[test]
fn remove_validator_emits_event() {
	ExtBuilder::default()
		.validators(vec![1, 2])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 1));
			System::assert_last_event(Event::ValidatorRemoved { validator: 1 }.into());
		});
}

#[test]
fn remove_validator_fails_if_not_approved() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::remove_validator(RuntimeOrigin::root(), 99),
				Error::<Test>::NotValidator
			);
		});
}

#[test]
fn remove_validator_requires_root() {
	ExtBuilder::default()
		.validators(vec![1, 2])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::remove_validator(RuntimeOrigin::signed(1), 2),
				sp_runtime::traits::BadOrigin
			);
		});
}

// ── OnValidatorRemoved hook ───────────────────────────────────────────────────

#[test]
fn remove_validator_fires_removal_hook() {
	ExtBuilder::default()
		.validators(vec![1, 2])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 2));
			assert_eq!(removed_hook_calls(), vec![2u64]);
		});
}

#[test]
fn deregister_validator_fires_removal_hook() {
	ExtBuilder::default()
		.validators(vec![42])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			assert_eq!(removed_hook_calls(), vec![42u64]);
		});
}

#[test]
fn failed_removal_does_not_fire_hook() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::remove_validator(RuntimeOrigin::root(), 99),
				Error::<Test>::NotValidator
			);
			assert!(removed_hook_calls().is_empty());
		});
}

// ── deregister_validator (signed) ─────────────────────────────────────────────

#[test]
fn deregister_removes_account_from_approved() {
	ExtBuilder::default()
		.validators(vec![1, 42])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			assert!(!ApprovedValidators::<Test>::get().contains(&42));
			assert!(ApprovedValidators::<Test>::get().contains(&1));
		});
}

#[test]
fn deregister_emits_event() {
	ExtBuilder::default()
		.validators(vec![1, 42])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			System::assert_last_event(Event::ValidatorRemoved { validator: 42 }.into());
		});
}

#[test]
fn deregister_fails_if_not_approved() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::deregister_validator(RuntimeOrigin::signed(42)),
				Error::<Test>::NotValidator
			);
		});
}

#[test]
fn deregister_does_not_touch_balances() {
	ExtBuilder::default()
		.validators(vec![42])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			assert_eq!(Balances::reserved_balance(42u64), 0);
			assert_eq!(Balances::free_balance(42u64), 10_000);
		});
}

// ── Round-trips ───────────────────────────────────────────────────────────────

#[test]
fn add_then_remove_leaves_set_unchanged() {
	ExtBuilder::default()
		.validators(vec![1, 2])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 99));
			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 99));
			let approved = ApprovedValidators::<Test>::get();
			assert!(!approved.contains(&99));
			assert_eq!(approved.len(), 2);
		});
}

#[test]
fn can_be_re_added_after_deregister() {
	ExtBuilder::default()
		.validators(vec![1, 42])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			// Leaving the set does not block being added again.
			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 42));
			assert!(ApprovedValidators::<Test>::get().contains(&42));
		});
}

// ── Hardening ────────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "Initial validators must not list an account twice")]
fn genesis_refuses_an_account_listed_twice() {
	// Removing it would drop one entry and leave it approved.
	ExtBuilder::default().validators(vec![10, 20, 10]).build();
}

#[test]
fn removal_drops_the_declared_version() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			LastAuthorVersion::<Test>::insert(1, (NodeVersion::new(1, 0, 0), 1));
			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 1));
			assert!(LastAuthorVersion::<Test>::get(1).is_none());
			assert_ok!(ValidatorSet::do_try_state());
		});
}
