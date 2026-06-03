use frame_support::{assert_noop, assert_ok};

use crate::{ApprovedValidators, Error, Event, PendingValidators, ValidatorBondOf, mock::*};
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
				frame_support::error::BadOrigin
			);
		});
}

#[test]
fn add_validator_fails_if_account_is_pending() {
	// A pending applicant must go through approve_validator, not be bypassed by sudo add.
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_noop!(
				ValidatorSet::add_validator(RuntimeOrigin::root(), 42),
				Error::<Test>::AlreadyPending
			);
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
fn remove_validator_fails_if_not_in_approved_or_pending() {
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
				frame_support::error::BadOrigin
			);
		});
}

#[test]
fn remove_validator_can_cancel_pending_registration() {
	// Sudo can force-cancel a pending applicant and their bond is returned.
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert!(PendingValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 1_000);

			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 42));

			assert!(!PendingValidators::<Test>::get().contains(&42));
			assert!(!ApprovedValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 0);
			assert_eq!(ValidatorBondOf::<Test>::get(42u64), None);
		});
}

#[test]
fn remove_validator_releases_bond_of_approved_self_registered() {
	// Sudo removes an approved self-registered validator; bond is returned.
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));
			assert_eq!(Balances::reserved_balance(42u64), 1_000);

			assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 42));

			assert_eq!(Balances::reserved_balance(42u64), 0);
			assert_eq!(ValidatorBondOf::<Test>::get(42u64), None);
		});
}

// ── register_validator (signed) ───────────────────────────────────────────────

#[test]
fn register_validator_goes_to_pending_not_approved() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));

			// Must be in pending, NOT in approved.
			assert!(PendingValidators::<Test>::get().contains(&42));
			assert!(!ApprovedValidators::<Test>::get().contains(&42));
		});
}

#[test]
fn register_validator_reserves_bond() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_eq!(Balances::reserved_balance(42u64), 1_000);
			assert_eq!(Balances::free_balance(42u64), 10_000 - 1_000);
			assert_eq!(ValidatorBondOf::<Test>::get(42u64), Some(1_000));
		});
}

#[test]
fn register_validator_emits_events() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			let events = System::events();
			assert!(events.iter().any(|r| matches!(
				&r.event,
				RuntimeEvent::ValidatorSet(Event::ValidatorBondReserved {
					validator: 42,
					amount: 1_000,
				})
			)));
			assert!(events.iter().any(|r| matches!(
				&r.event,
				RuntimeEvent::ValidatorSet(Event::ValidatorRegistrationRequested { validator: 42 })
			)));
		});
}

#[test]
fn register_validator_fails_if_already_approved() {
	ExtBuilder::default()
		.validators(vec![42])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::register_validator(RuntimeOrigin::signed(42)),
				Error::<Test>::AlreadyValidator
			);
		});
}

#[test]
fn register_validator_fails_if_already_pending() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_noop!(
				ValidatorSet::register_validator(RuntimeOrigin::signed(42)),
				Error::<Test>::AlreadyPending
			);
		});
}

#[test]
fn register_validator_fails_if_no_session_keys() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			set_mock_session_keys(false);
			assert_noop!(
				ValidatorSet::register_validator(RuntimeOrigin::signed(42)),
				Error::<Test>::NoSessionKeys
			);
			set_mock_session_keys(true);
		});
}

#[test]
fn register_validator_fails_if_no_relayer() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			set_mock_relayer(false);
			assert_noop!(
				ValidatorSet::register_validator(RuntimeOrigin::signed(42)),
				Error::<Test>::NoRelayer
			);
			set_mock_relayer(true);
		});
}

#[test]
fn register_validator_fails_if_insufficient_balance() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			// Account 999 has no pre-funded balance.
			assert_noop!(
				ValidatorSet::register_validator(RuntimeOrigin::signed(999)),
				Error::<Test>::InsufficientBond
			);
		});
}

#[test]
fn register_validator_fails_when_pending_queue_is_full() {
	// MaxPendingValidators = 10. Fill the pending queue then try one more.
	ExtBuilder::default()
		.validators(vec![]) // empty approved set so genesis accounts can register
		.build()
		.execute_with(|| {
			// 7 funded accounts from ExtBuilder (10,20,30,42,99,100,200).
			for acc in [10u64, 20, 30, 42, 99, 100, 200] {
				assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(acc)));
			}
			// Top up 3 more accounts inline.
			use frame_support::traits::fungible::Mutate;
			for acc in [201u64, 202, 203] {
				Balances::set_balance(&acc, 10_000);
				assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(acc)));
			}
			assert_eq!(PendingValidators::<Test>::get().len(), 10);

			Balances::set_balance(&999u64, 10_000);
			assert_noop!(
				ValidatorSet::register_validator(RuntimeOrigin::signed(999)),
				Error::<Test>::TooManyPending
			);
		});
}

// ── approve_validator (sudo) ──────────────────────────────────────────────────

#[test]
fn approve_validator_moves_pending_to_approved() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));

			assert!(!PendingValidators::<Test>::get().contains(&42));
			assert!(ApprovedValidators::<Test>::get().contains(&42));
		});
}

#[test]
fn approve_validator_does_not_release_bond() {
	// Bond stays locked after approval; the validator is active.
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));

			assert_eq!(Balances::reserved_balance(42u64), 1_000);
			assert_eq!(ValidatorBondOf::<Test>::get(42u64), Some(1_000));
		});
}

#[test]
fn approve_validator_emits_event() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));
			System::assert_last_event(Event::ValidatorApproved { validator: 42 }.into());
		});
}

#[test]
fn approve_validator_fails_if_not_pending() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::approve_validator(RuntimeOrigin::root(), 42),
				Error::<Test>::NotPending
			);
		});
}

#[test]
fn approve_validator_fails_when_approved_set_is_full() {
	let full: Vec<u64> = (1..=10).collect();
	ExtBuilder::default()
		.validators(full)
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			// Approved set is already full (10/10).
			assert_noop!(
				ValidatorSet::approve_validator(RuntimeOrigin::root(), 42),
				Error::<Test>::TooManyValidators
			);
			// Applicant remains pending, bond not lost.
			assert!(PendingValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 1_000);
		});
}

#[test]
fn approve_validator_requires_root() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_noop!(
				ValidatorSet::approve_validator(RuntimeOrigin::signed(1), 42),
				frame_support::error::BadOrigin
			);
		});
}

// ── reject_validator (sudo) ───────────────────────────────────────────────────

#[test]
fn reject_validator_removes_from_pending_and_releases_bond() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_eq!(Balances::reserved_balance(42u64), 1_000);

			assert_ok!(ValidatorSet::reject_validator(RuntimeOrigin::root(), 42));

			assert!(!PendingValidators::<Test>::get().contains(&42));
			assert!(!ApprovedValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 0);
			assert_eq!(Balances::free_balance(42u64), 10_000);
			assert_eq!(ValidatorBondOf::<Test>::get(42u64), None);
		});
}

#[test]
fn reject_validator_emits_events() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::reject_validator(RuntimeOrigin::root(), 42));
			let events = System::events();
			assert!(events.iter().any(|r| matches!(
				&r.event,
				RuntimeEvent::ValidatorSet(Event::ValidatorBondReleased {
					validator: 42,
					amount: 1_000,
				})
			)));
			assert!(events.iter().any(|r| matches!(
				&r.event,
				RuntimeEvent::ValidatorSet(Event::ValidatorRejected { validator: 42 })
			)));
		});
}

#[test]
fn reject_validator_fails_if_not_pending() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::reject_validator(RuntimeOrigin::root(), 42),
				Error::<Test>::NotPending
			);
		});
}

#[test]
fn reject_validator_requires_root() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_noop!(
				ValidatorSet::reject_validator(RuntimeOrigin::signed(1), 42),
				frame_support::error::BadOrigin
			);
		});
}

// ── deregister_validator (signed) ─────────────────────────────────────────────

#[test]
fn deregister_from_approved_removes_and_releases_bond() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));
			let free_after_register = Balances::free_balance(42u64);

			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));

			assert!(!ApprovedValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 0);
			assert_eq!(Balances::free_balance(42u64), free_after_register + 1_000);
			assert_eq!(ValidatorBondOf::<Test>::get(42u64), None);
		});
}

#[test]
fn deregister_from_pending_removes_and_releases_bond() {
	// Candidate changes their mind before approval — bond must be returned.
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert!(PendingValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 1_000);

			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));

			assert!(!PendingValidators::<Test>::get().contains(&42));
			assert!(!ApprovedValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 0);
			assert_eq!(Balances::free_balance(42u64), 10_000);
			assert_eq!(ValidatorBondOf::<Test>::get(42u64), None);
		});
}

#[test]
fn deregister_emits_events() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			let events = System::events();
			assert!(events.iter().any(|r| matches!(
				&r.event,
				RuntimeEvent::ValidatorSet(Event::ValidatorBondReleased {
					validator: 42,
					amount: 1_000,
				})
			)));
			assert!(events.iter().any(|r| matches!(
				&r.event,
				RuntimeEvent::ValidatorSet(Event::ValidatorRemoved { validator: 42 })
			)));
		});
}

#[test]
fn deregister_fails_if_not_in_pending_or_approved() {
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
fn deregister_no_bond_if_added_via_sudo() {
	// Validators added via sudo have no bond — deregister should still work cleanly.
	ExtBuilder::default()
		.validators(vec![42])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			assert!(!ApprovedValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 0);
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
fn pending_validator_not_included_in_session() {
	// A self-registered (pending) validator must NOT appear in the active session.
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			let validators = <ValidatorSet as SessionManager<u64>>::new_session(1).unwrap();
			assert!(!validators.contains(&42u64));
		});
}

#[test]
fn approved_validator_appears_in_next_session() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));
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
fn register_approve_deregister_full_flow() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			// 1. Register → pending, bond locked.
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert!(PendingValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 1_000);

			// 2. Approve → approved, bond still locked.
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));
			assert!(!PendingValidators::<Test>::get().contains(&42));
			assert!(ApprovedValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 1_000);

			// 3. Deregister → removed, bond returned.
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			assert!(!ApprovedValidators::<Test>::get().contains(&42));
			assert_eq!(Balances::reserved_balance(42u64), 0);
			assert_eq!(Balances::free_balance(42u64), 10_000);
		});
}

#[test]
fn register_reject_then_re_register_works() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::reject_validator(RuntimeOrigin::root(), 42));
			// Bond returned — can register again.
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert!(PendingValidators::<Test>::get().contains(&42));
		});
}

#[test]
fn can_re_register_after_deregister_from_approved() {
	ExtBuilder::default()
		.validators(vec![1])
		.build()
		.execute_with(|| {
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert_ok!(ValidatorSet::approve_validator(RuntimeOrigin::root(), 42));
			assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(
				42
			)));
			// Bond was released — can register again immediately.
			assert_ok!(ValidatorSet::register_validator(RuntimeOrigin::signed(42)));
			assert!(PendingValidators::<Test>::get().contains(&42));
		});
}
