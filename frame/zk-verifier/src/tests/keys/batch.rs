//! `batch_register_verification_keys`.

use crate::tests::util::*;
use crate::{
	ActiveCircuitVersion, CircuitId, Error, Event, VerificationKeys, VkEntry, tests::mock::*,
};
use frame_support::{assert_noop, assert_ok};
use orbinum_zk_verifier::TRANSFER_PUBLIC_INPUTS;

#[test]
fn batch_register_requires_root() {
	new_test_ext().execute_with(|| {
		let entry = make_vk_entry(CircuitId::TRANSFER, 1, false);
		let entries = batch(vec![entry]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(signed().into(), entries),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn batch_register_rejects_empty_entries() {
	new_test_ext().execute_with(|| {
		let entries = batch(vec![]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::InvalidBatchSize
		);
	});
}

#[test]
fn batch_register_rejects_empty_vk() {
	new_test_ext().execute_with(|| {
		let bad = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			verification_key: vk_empty(),
			set_active: false,
		};
		let entries = batch(vec![bad]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::EmptyVerificationKey
		);
	});
}

/// The batch path holds keys to the same rule: no base spend key, even as v1.
#[test]
fn batch_register_refuses_a_base_spend_key() {
	new_test_ext().execute_with(|| {
		let bad = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			verification_key: real_vk(TRANSFER_PUBLIC_INPUTS),
			set_active: true,
		};
		let entries = batch(vec![bad]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

#[test]
fn batch_register_rejects_short_vk() {
	new_test_ext().execute_with(|| {
		let bad = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			verification_key: vk_too_short(),
			set_active: false,
		};
		let entries = batch(vec![bad]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

#[test]
fn batch_register_stores_all_keys_and_emits_count() {
	new_test_ext().execute_with(|| {
		let entries = batch(vec![
			make_vk_entry(CircuitId::TRANSFER, 1, false),
			make_vk_entry(CircuitId::UNSHIELD, 1, false),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1u32
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::UNSHIELD,
			1u32
		));
		assert!(has_event(Event::BatchVerificationKeysRegistered {
			count: 2
		}));
	});
}

#[test]
fn batch_register_auto_activates_when_no_active_version_exists() {
	new_test_ext().execute_with(|| {
		let entries = batch(vec![make_vk_entry(CircuitId::TRANSFER, 1, false)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}

#[test]
fn batch_register_set_active_true_overrides_existing_active_version() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		let entries = batch(vec![make_vk_entry(CircuitId::TRANSFER, 2, true)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(2u32)
		);
	});
}

#[test]
fn batch_register_set_active_false_does_not_override_existing_active_version() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		let entries = batch(vec![make_vk_entry(CircuitId::TRANSFER, 2, false)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		// Active must remain v1.
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}

#[test]
fn batch_register_up_to_ten_entries_is_accepted() {
	new_test_ext().execute_with(|| {
		// Use different versions of the same circuit to fill 10 slots.
		let entries = batch(
			(1u32..=10)
				.map(|v| make_vk_entry(CircuitId::TRANSFER, v, false))
				.collect(),
		);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		assert!(has_event(Event::BatchVerificationKeysRegistered {
			count: 10
		}));
	});
}

#[test]
fn batch_register_rejects_duplicate_circuit_version() {
	// An entry that would overwrite an existing (circuit_id, version) fails the
	// whole batch atomically — no partial state changes.
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);

		// Version 1 already exists.
		let entries = batch(vec![make_vk_entry(CircuitId::TRANSFER, 1, false)]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::CircuitAlreadyExists
		);
	});
}
