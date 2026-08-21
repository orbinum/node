//! `clear_relayer`: the cleanup the runtime runs when a validator leaves the set.
//!
//! Must be infallible and idempotent — removal from the validator set can never
//! be blocked by cleanup failing.

use crate::{
	Event, PendingRelayerFees, RelayerByAccount, RelayerRegistry, mock::*, traits::RelayerInterface,
};
use frame_support::assert_ok;
use sp_core::H160;

// ─── clear_relayer (runtime hook for validators leaving the set) ──────────────

#[test]
fn clear_relayer_removes_both_indices() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);

		assert_eq!(crate::Pallet::<Test>::clear_relayer(&1u64), Some(evm));

		assert!(!RelayerRegistry::<Test>::contains_key(evm));
		assert!(!RelayerByAccount::<Test>::contains_key(1u64));
	});
}

#[test]
fn clear_relayer_emits_unregistered_event() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);

		crate::Pallet::<Test>::clear_relayer(&1u64);

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
fn clear_relayer_is_idempotent_and_silent_when_unregistered() {
	new_test_ext().execute_with(|| {
		// Never registered — must not panic and must not emit.
		assert_eq!(crate::Pallet::<Test>::clear_relayer(&1u64), None);
		assert!(System::events().is_empty());

		set_mock_validator(1);
		assert_ok!(register_with_proof(1, seeds::ALICE).1);
		assert!(crate::Pallet::<Test>::clear_relayer(&1u64).is_some());

		let after_first = System::events().len();
		// Second call has nothing left to do, so it must not emit either.
		assert_eq!(crate::Pallet::<Test>::clear_relayer(&1u64), None);
		assert_eq!(System::events().len(), after_first);
		assert!(!RelayerByAccount::<Test>::contains_key(1u64));
	});
}

#[test]
fn clear_relayer_preserves_pending_fees() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		assert_ok!(register_with_proof(1, seeds::ALICE).1);
		// Fees already earned must survive: clearing the binding is not confiscation.
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 5_000u128);

		crate::Pallet::<Test>::clear_relayer(&1u64);

		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 5_000u128);
	});
}

#[test]
fn clear_relayer_frees_the_address_for_its_owner_to_reclaim() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);

		crate::Pallet::<Test>::clear_relayer(&1u64);

		// Re-added to the set later, the same operator reclaims the same address.
		assert_ok!(register_with_proof(1, seeds::ALICE).1);
		assert_eq!(RelayerRegistry::<Test>::get(evm), Some(1u64));
	});
}

#[test]
fn clear_relayer_tolerates_a_half_written_registry() {
	// No code path produces this, but the helper must not misbehave if one ever
	// does: a forward entry with no reverse entry is left alone, not panicked on.
	new_test_ext().execute_with(|| {
		let orphan = H160::repeat_byte(0x7f);
		RelayerRegistry::<Test>::insert(orphan, 1u64);

		assert_eq!(crate::Pallet::<Test>::clear_relayer(&1u64), None);

		// Pivoting on RelayerByAccount means the orphan survives — documented
		// here so a future change to the pivot is a deliberate one.
		assert_eq!(RelayerRegistry::<Test>::get(orphan), Some(1u64));
	});
}
