// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The runtime API's circuit version queries.

use crate::{CircuitId, Pallet, tests::mock::*};
use orbinum_zk_verifier::{TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS};

#[test]
fn runtime_api_circuit_version_info_returns_none_for_unknown_circuit() {
	new_test_ext().execute_with(|| {
		assert!(
			Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0).is_none()
		);
	});
}

#[test]
fn runtime_api_circuit_version_info_returns_none_when_no_active_version() {
	// VK registered but active version never set.
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		assert!(
			Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0).is_none()
		);
	});
}

#[test]
fn runtime_api_circuit_version_info_returns_correct_fields() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let info = Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0)
			.expect("should be Some");
		assert_eq!(info.circuit_id, CircuitId::TRANSFER.0);
		assert_eq!(info.active_version, 1u32);
		assert_eq!(info.supported_versions, vec![1u32, 2u32]);
		assert_eq!(info.vk_hashes.len(), 2);
	});
}

#[test]
fn runtime_api_circuit_version_info_supported_versions_are_sorted() {
	new_test_ext().execute_with(|| {
		// Insert in reverse order — result must still be sorted.
		insert_vk(CircuitId::TRANSFER, 3, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let info =
			Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0).unwrap();
		assert_eq!(info.supported_versions, vec![1u32, 2u32, 3u32]);
	});
}

#[test]
fn runtime_api_circuit_version_info_vk_hashes_are_blake2_256_of_key_data() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let info =
			Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0).unwrap();
		let expected_hash = sp_io::hashing::blake2_256(&real_vk(TRANSFER_PUBLIC_INPUTS));
		assert_eq!(info.vk_hashes[0].vk_hash, expected_hash);
		assert_eq!(info.vk_hashes[0].version, 1u32);
	});
}

#[test]
fn runtime_api_all_circuit_versions_empty_when_nothing_registered() {
	new_test_ext().execute_with(|| {
		assert!(Pallet::<Test>::runtime_api_get_all_circuit_versions().is_empty());
	});
}

#[test]
fn runtime_api_all_circuit_versions_returns_all_active_circuits() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		activate(CircuitId::UNSHIELD, 1);

		let all = Pallet::<Test>::runtime_api_get_all_circuit_versions();
		assert_eq!(all.len(), 2);
		let ids: Vec<u32> = all.iter().map(|i| i.circuit_id).collect();
		assert!(ids.contains(&CircuitId::TRANSFER.0));
		assert!(ids.contains(&CircuitId::UNSHIELD.0));
	});
}

#[test]
fn runtime_api_all_circuit_versions_excludes_circuits_with_no_active_version() {
	new_test_ext().execute_with(|| {
		// TRANSFER has a VK but no active version → excluded.
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS);
		activate(CircuitId::UNSHIELD, 1);

		let all = Pallet::<Test>::runtime_api_get_all_circuit_versions();
		assert_eq!(all.len(), 1);
		assert_eq!(all[0].circuit_id, CircuitId::UNSHIELD.0);
	});
}

/// A version whose key is denied is not offered: pool admission would refuse it.
#[test]
fn runtime_api_circuit_version_info_omits_denied_keys() {
	new_test_ext().execute_with(|| {
		let denied = denied_vk_of(TRANSFER_PUBLIC_INPUTS);
		insert_key(CircuitId::TRANSFER, 1, denied.clone());
		crate::VkHashes::<Test>::insert(
			CircuitId::TRANSFER,
			1,
			sp_io::hashing::blake2_256(&denied),
		);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 2);
		crate::DeniedVkHashes::<Test>::insert(sp_io::hashing::blake2_256(&denied), ());

		let info = Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0)
			.expect("version 2 is usable");
		assert_eq!(info.supported_versions, vec![2u32]);
		assert_eq!(info.vk_hashes.len(), 1);
	});
}
