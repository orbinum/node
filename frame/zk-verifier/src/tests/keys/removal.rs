//! `remove_verification_key`: what it removes and what it keeps.

use crate::tests::util::*;
use crate::{
	ActiveCircuitVersion, CircuitId, Error, Event, RetiredVersions, VerificationKeys,
	VerificationStatistics, VerificationStats, VkHashes, tests::mock::*,
};
use frame_support::{assert_noop, assert_ok};
use orbinum_zk_verifier::TRANSFER_PUBLIC_INPUTS;

#[test]
fn remove_vk_requires_root() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::remove_verification_key(signed().into(), CircuitId::TRANSFER, 1),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn remove_vk_rejects_non_existent_key() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 99),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn remove_vk_cannot_remove_active_version() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		assert_noop!(
			ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::CannotRemoveActiveVersion
		);
	});
}

#[test]
fn remove_vk_returns_active_version_not_set_when_no_active_exists() {
	new_test_ext().execute_with(|| {
		// VK exists but no active version is set.
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		assert_noop!(
			ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::ActiveVersionNotSet
		);
	});
}

#[test]
fn remove_vk_happy_path_removes_key_and_emits_event() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(!VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			2u32
		));
		assert!(has_event(Event::VerificationKeyRemoved {
			circuit_id: CircuitId::TRANSFER,
			version: 2
		}));
	});
}

#[test]
fn remove_vk_active_version_is_preserved_after_removal() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		// Active version must still be 1.
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}

#[test]
fn removing_a_vk_clears_its_retirement_flag() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		assert_ok!(ZkVerifier::retire_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(!RetiredVersions::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
	});
}

/// `remove_verification_key` clears the satellite maps with the key, so it
/// leaves no orphans behind for `purge_circuit` to collect.
#[test]
fn remove_vk_also_clears_hash_and_stats() {
	new_test_ext().execute_with(|| {
		let cid = CircuitId::TRANSFER;
		seed_circuit(cid, 1, TRANSFER_PUBLIC_INPUTS);
		seed_circuit(cid, 2, TRANSFER_PUBLIC_INPUTS);
		activate(cid, 1);
		VerificationStats::<Test>::insert(cid, 2, VerificationStatistics::default());

		assert_ok!(ZkVerifier::remove_verification_key(root().into(), cid, 2));

		assert!(VkHashes::<Test>::get(cid, 2).is_none());
		assert!(!VerificationStats::<Test>::contains_key(cid, 2));
		// The active version is untouched.
		assert!(VerificationKeys::<Test>::get(cid, 1).is_some());
		assert!(VkHashes::<Test>::get(cid, 1).is_some());
	});
}
