// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! `retire_version` and `unretire_version`.

use crate::tests::util::*;
use crate::{CircuitId, Error, Event, RetiredVersions, tests::mock::*};
use frame_support::{assert_noop, assert_ok};
use orbinum_zk_verifier::{MEMO_HASH_INPUTS, TRANSFER_PUBLIC_INPUTS};

#[test]
fn retire_version_requires_root() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		assert_noop!(
			ZkVerifier::retire_version(signed().into(), CircuitId::TRANSFER, 2),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn retire_version_rejects_active_and_unknown() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		// active version cannot be retired
		assert_noop!(
			ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::CannotRetireActiveVersion
		);
		// unknown version cannot be retired
		assert_noop!(
			ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 9),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn retire_then_unretire_toggles_the_flag() {
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

		assert_ok!(ZkVerifier::retire_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(RetiredVersions::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		assert!(has_event(Event::VersionRetired {
			circuit_id: CircuitId::TRANSFER,
			version: 2
		}));
		// double-retire rejected
		assert_noop!(
			ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 2),
			Error::<Test>::VersionAlreadyRetired
		);

		assert_ok!(ZkVerifier::unretire_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(!RetiredVersions::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		// unretire of a non-retired version rejected
		assert_noop!(
			ZkVerifier::unretire_version(root().into(), CircuitId::TRANSFER, 2),
			Error::<Test>::VersionNotRetired
		);
	});
}
