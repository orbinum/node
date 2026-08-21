//! Registration lifecycle of the EVM address ↔ AccountId binding.
//!
//! Covers `register_relayer`'s non-cryptographic guards, `unregister_relayer`,
//! and the `RelayerInterface` reverse lookup. The ownership proof has its own
//! file ([`super::ownership_proof_tests`]), as does the cleanup hook
//! ([`super::cleanup_tests`]).

use crate::{Error, Event, RelayerByAccount, RelayerRegistry, mock::*, traits::RelayerInterface};
use frame_support::{assert_noop, assert_ok};

// ─── register_relayer ────────────────────────────────────────────────────────

#[test]
fn approved_validator_can_register_relayer() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);
		assert_eq!(RelayerRegistry::<Test>::get(evm), Some(1u64));
		assert_eq!(RelayerByAccount::<Test>::get(1u64), Some(evm));
	});
}

#[test]
fn register_emits_event() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);
		System::assert_last_event(
			Event::RelayerRegistered {
				evm_address: evm,
				account: 1u64,
			}
			.into(),
		);
	});
}

#[test]
fn register_relayer_fails_when_not_a_validator() {
	new_test_ext().execute_with(|| {
		// Account 1 is not in the validator set — this is what stops an arbitrary
		// account from claiming an EVM address now that the call is self-service.
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_noop!(result, Error::<Test>::NotValidator);
		assert!(!RelayerRegistry::<Test>::contains_key(evm));
	});
}

#[test]
fn register_relayer_fails_once_removed_from_the_validator_set() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		clear_mock_validator(1);
		let (_, result) = register_with_proof(1, seeds::ALICE);
		assert_noop!(result, Error::<Test>::NotValidator);
	});
}

#[test]
fn register_relayer_requires_signed() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, sig) = proof_for(1, seeds::ALICE);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::none(), evm, sig.clone()),
			frame_support::error::BadOrigin,
		);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::root(), evm, sig),
			frame_support::error::BadOrigin,
		);
	});
}

// ─── Duplicate guards ────────────────────────────────────────────────────────

#[test]
fn register_fails_if_evm_already_taken() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		set_mock_validator(2);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);
		// Account 2 would need account 1's key to even produce this signature; the
		// test writes it directly to isolate the AlreadyRegistered guard.
		let (_, sig_for_2) = proof_for(2, seeds::ALICE);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(2), evm, sig_for_2),
			Error::<Test>::AlreadyRegistered,
		);
	});
}

#[test]
fn a_failed_duplicate_registration_leaves_the_reverse_index_clean() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		set_mock_validator(2);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);

		let (_, sig_for_2) = proof_for(2, seeds::ALICE);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(2), evm, sig_for_2),
			Error::<Test>::AlreadyRegistered,
		);

		// Neither index may have moved.
		assert!(!RelayerByAccount::<Test>::contains_key(2u64));
		assert_eq!(RelayerRegistry::<Test>::get(evm), Some(1u64));
	});
}

#[test]
fn register_fails_if_account_already_registered() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		assert_ok!(register_with_proof(1, seeds::ALICE).1);
		let (second, result) = register_with_proof(1, seeds::BOB);
		assert_noop!(result, Error::<Test>::AccountAlreadyRegistered);
		// The second address must not have been claimed.
		assert!(!RelayerRegistry::<Test>::contains_key(second));
	});
}

#[test]
fn two_validators_can_register_different_evm_addresses() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		set_mock_validator(2);
		let (evm1, r1) = register_with_proof(1, seeds::ALICE);
		let (evm2, r2) = register_with_proof(2, seeds::BOB);
		assert_ok!(r1);
		assert_ok!(r2);
		assert_ne!(evm1, evm2);
		assert_eq!(RelayerRegistry::<Test>::get(evm1), Some(1u64));
		assert_eq!(RelayerRegistry::<Test>::get(evm2), Some(2u64));
	});
}

#[test]
fn registration_works_at_the_top_of_the_validator_set() {
	// The gate scans the whole set; the last member must still get through.
	new_test_ext().execute_with(|| {
		for who in 1..=32u64 {
			set_mock_validator(who);
		}
		let (evm, result) = register_with_proof(32, seeds::CAROL);
		assert_ok!(result);
		assert_eq!(RelayerRegistry::<Test>::get(evm), Some(32u64));
	});
}

// ─── unregister_relayer ──────────────────────────────────────────────────────

#[test]
fn unregister_works() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(1)));
		assert!(!RelayerRegistry::<Test>::contains_key(evm));
		assert!(!RelayerByAccount::<Test>::contains_key(1u64));
	});
}

#[test]
fn unregister_emits_event() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(1)));
		System::assert_last_event(
			Event::RelayerUnregistered {
				evm_address: evm,
				account: 1u64,
			}
			.into(),
		);
	});
}

#[test]
fn unregister_fails_if_not_registered() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::unregister_relayer(RuntimeOrigin::signed(1)),
			Error::<Test>::NotRegistered,
		);
	});
}

#[test]
fn unregister_requires_signed() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::unregister_relayer(RuntimeOrigin::none()),
			frame_support::error::BadOrigin,
		);
	});
}

#[test]
fn can_re_register_after_unregister() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(1)));
		// Unregistering frees both the account and the address.
		assert_ok!(register_with_proof(1, seeds::ALICE).1);
		assert_eq!(RelayerRegistry::<Test>::get(evm), Some(1u64));
	});
}

#[test]
fn unregister_frees_the_address_for_its_owner_only() {
	// Another validator still cannot take it — they lack the key.
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		set_mock_validator(2);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(1)));

		let (_, sig_for_2) = proof_for(2, seeds::BOB);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(2), evm, sig_for_2),
			Error::<Test>::BadEvmSignature,
		);
	});
}

// ─── registered_evm_address (RelayerInterface reverse lookup) ────────────────

#[test]
fn registered_evm_address_returns_none_for_unknown_account() {
	new_test_ext().execute_with(|| {
		assert_eq!(crate::Pallet::<Test>::registered_evm_address(&1u64), None);
	});
}

#[test]
fn registered_evm_address_returns_correct_address() {
	new_test_ext().execute_with(|| {
		set_mock_validator(100);
		let (evm, result) = register_with_proof(100, seeds::ALICE);
		assert_ok!(result);
		assert_eq!(
			crate::Pallet::<Test>::registered_evm_address(&100u64),
			Some(evm),
		);
	});
}

#[test]
fn registered_evm_address_returns_none_after_unregister() {
	new_test_ext().execute_with(|| {
		set_mock_validator(100);
		assert_ok!(register_with_proof(100, seeds::ALICE).1);
		assert_ok!(Relayer::unregister_relayer(RuntimeOrigin::signed(100)));
		assert_eq!(crate::Pallet::<Test>::registered_evm_address(&100u64), None);
	});
}

#[test]
fn registered_evm_address_is_account_specific() {
	new_test_ext().execute_with(|| {
		set_mock_validator(100);
		set_mock_validator(101);
		let (evm_a, r1) = register_with_proof(100, seeds::ALICE);
		let (evm_b, r2) = register_with_proof(101, seeds::BOB);
		assert_ok!(r1);
		assert_ok!(r2);
		assert_eq!(
			crate::Pallet::<Test>::registered_evm_address(&100u64),
			Some(evm_a),
		);
		assert_eq!(
			crate::Pallet::<Test>::registered_evm_address(&101u64),
			Some(evm_b),
		);
	});
}
