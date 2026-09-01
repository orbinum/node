use frame_support::{assert_noop, assert_ok};

use crate::{ApprovedValidators, Error, Event, mock::*};
use pallet_session::SessionManager;

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

// ── ValidatorSetInterface (consumed by pallet-relayer) ────────────────────────

#[test]
fn interface_reports_membership() {
	use crate::ValidatorSetInterface;

	ExtBuilder::default()
		.validators(vec![1, 2])
		.build()
		.execute_with(|| {
			assert!(<ValidatorSet as ValidatorSetInterface<u64>>::is_active_validator(&1));
			assert!(!<ValidatorSet as ValidatorSetInterface<u64>>::is_active_validator(&99));
		});
}

#[test]
fn interface_tracks_additions_and_removals() {
	// This is the gate pallet-relayer depends on: an account must stop being an
	// active validator the moment it leaves the set, or its EVM binding could
	// outlive the membership that authorised it.
	use crate::ValidatorSetInterface;

	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert!(!<ValidatorSet as ValidatorSetInterface<u64>>::is_active_validator(&42));

			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 42));
			assert!(<ValidatorSet as ValidatorSetInterface<u64>>::is_active_validator(&42));

			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 42));
			assert!(!<ValidatorSet as ValidatorSetInterface<u64>>::is_active_validator(&42));
		});
}

#[test]
fn interface_reports_false_on_an_empty_set() {
	use crate::ValidatorSetInterface;

	ExtBuilder::default()
		.validators(vec![])
		.build()
		.execute_with(|| {
			assert!(!<ValidatorSet as ValidatorSetInterface<u64>>::is_active_validator(&1));
		});
}

// ── SessionManager integration ────────────────────────────────────────────────

#[test]
fn new_session_returns_current_approved_set() {
	ExtBuilder::default()
		.validators(vec![10, 20])
		.build()
		.execute_with(|| {
			let validators = <ValidatorSet as SessionManager<u64>>::new_session(1).unwrap();
			assert_eq!(validators, vec![10u64, 20]);
		});
}

#[test]
fn new_session_reflects_added_validator() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 5));
			let validators = <ValidatorSet as SessionManager<u64>>::new_session(2).unwrap();
			assert_eq!(validators, vec![1u64, 5]);
		});
}

#[test]
fn new_session_reflects_removed_validator() {
	ExtBuilder::default()
		.validators(vec![1, 2, 3])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 2));
			let validators = <ValidatorSet as SessionManager<u64>>::new_session(2).unwrap();
			assert_eq!(validators, vec![1u64, 3]);
		});
}

#[test]
fn new_session_genesis_returns_same_as_new_session() {
	ExtBuilder::default()
		.validators(vec![7, 8])
		.build()
		.execute_with(|| {
			let via_genesis =
				<ValidatorSet as SessionManager<u64>>::new_session_genesis(0).unwrap();
			let via_new = <ValidatorSet as SessionManager<u64>>::new_session(0).unwrap();
			assert_eq!(via_genesis, via_new);
		});
}

#[test]
fn session_manager_start_and_end_are_noop() {
	ExtBuilder::default().build().execute_with(|| {
		<ValidatorSet as SessionManager<u64>>::start_session(0);
		<ValidatorSet as SessionManager<u64>>::end_session(0);
	});
}

#[test]
fn keyless_validators_are_kept_out_of_the_session() {
	// `session.purge_keys` is permissionless, so an approved validator can drop
	// its keys and would otherwise hold a slot while producing nothing.
	ExtBuilder::default()
		.validators(vec![1, 2])
		.build()
		.execute_with(|| {
			set_mock_session_keys(false);
			let validators = <ValidatorSet as SessionManager<u64>>::new_session(1).unwrap();
			assert!(
				validators.is_empty(),
				"no approved account can author without keys"
			);
			// They stay approved — only the session list is filtered.
			assert_eq!(ApprovedValidators::<Test>::get().len(), 2);
		});
}

#[test]
fn removing_the_last_validator_empties_the_set_and_the_session() {
	ExtBuilder::default()
		.validators(vec![42])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			assert!(ApprovedValidators::<Test>::get().is_empty());
			// An empty author list stalls block production; sudo must re-add.
			assert_eq!(
				<ValidatorSet as SessionManager<u64>>::new_session(2),
				Some(vec![])
			);
		});
}

#[test]
fn added_validator_appears_in_next_session() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 42));
			let validators = <ValidatorSet as SessionManager<u64>>::new_session(2).unwrap();
			assert!(validators.contains(&42u64));
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
