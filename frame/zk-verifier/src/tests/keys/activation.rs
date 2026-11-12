// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! `set_active_version`.

use crate::tests::util::*;
use crate::{ActiveCircuitVersion, CircuitId, Error, Event, RetiredVersions, tests::mock::*};
use frame_support::{assert_noop, assert_ok};
use orbinum_zk_verifier::{MEMO_HASH_INPUTS, TRANSFER_PUBLIC_INPUTS};

#[test]
fn set_active_version_requires_root() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::set_active_version(signed().into(), CircuitId::TRANSFER, 1),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn set_active_version_rejects_a_retired_version() {
	new_test_ext().execute_with(|| {
		insert_vk(
			CircuitId::TRANSFER,
			1,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		insert_vk(
			CircuitId::TRANSFER,
			2,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		RetiredVersions::<Test>::insert(CircuitId::TRANSFER, 1, ());
		assert_noop!(
			ZkVerifier::set_active_version(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::UnsupportedCircuitVersion
		);
		assert_ok!(ZkVerifier::set_active_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
	});
}

/// A base spend key already in storage — never registrable, but left by an
/// older runtime or a raw storage write — cannot be made active.
#[test]
fn set_active_version_refuses_a_base_spend_key() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		assert_noop!(
			ZkVerifier::set_active_version(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

#[test]
fn set_active_version_rejects_non_existent_vk() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::set_active_version(root().into(), CircuitId::TRANSFER, 99),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn set_active_version_updates_storage_and_emits_event() {
	new_test_ext().execute_with(|| {
		insert_vk(
			CircuitId::TRANSFER,
			1,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		insert_vk(
			CircuitId::TRANSFER,
			2,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::TRANSFER, 1);

		assert_ok!(ZkVerifier::set_active_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(2u32)
		);
		assert!(has_event(Event::ActiveVersionSet {
			circuit_id: CircuitId::TRANSFER,
			version: 2
		}));
	});
}

#[test]
fn set_active_version_can_downgrade() {
	new_test_ext().execute_with(|| {
		insert_vk(
			CircuitId::TRANSFER,
			1,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		insert_vk(
			CircuitId::TRANSFER,
			2,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::TRANSFER, 2);

		assert_ok!(ZkVerifier::set_active_version(
			root().into(),
			CircuitId::TRANSFER,
			1
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}
