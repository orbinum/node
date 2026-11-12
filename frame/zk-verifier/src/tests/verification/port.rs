// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! [`ZkVerifierPort`]: each statement verified under its circuit's keys.

use crate::{
	CircuitId, Error, Pallet, RetiredVersions, ShieldStatement, TransferStatement,
	UnshieldStatement, ZkVerifierPort, engine::port::MAX_SPEND_PUBLIC_INPUTS, tests::mock::*,
};
use frame_support::assert_err;
use orbinum_zk_verifier::{
	CROSS_TREE_INPUTS, MEMO_HASH_INPUTS, SHIELD_PUBLIC_INPUTS, TRANSFER_PUBLIC_INPUTS,
	UNSHIELD_PUBLIC_INPUTS,
};

// ── Helpers ───────────────────────────────────────────────────────────────

const NULLIFIERS: [[u8; 32]; 2] = [[0xAA; 32], [0xBB; 32]];
const COMMITMENTS: [[u8; 32]; 2] = [[0xCC; 32], [0xDD; 32]];

fn proof() -> alloc::vec::Vec<u8> {
	vec![0x01u8; 128]
}

fn transfer() -> TransferStatement {
	TransferStatement {
		merkle_roots: [[0x03; 32]; 2],
		nullifiers: NULLIFIERS.to_vec(),
		commitments: COMMITMENTS.to_vec(),
		asset_id: 1,
		fee: 500,
		memo_digest: [0x04; 32],
	}
}

fn unshield() -> UnshieldStatement {
	UnshieldStatement {
		merkle_root: [0x03; 32],
		nullifier: [0x02; 32],
		amount: 1000,
		recipient: [0xFF; 32],
		asset_id: 0,
		fee: 50,
		change_commitment: [0; 32],
		memo_digest: [0x04; 32],
	}
}

fn verify_transfer(
	s: &TransferStatement,
	version: Option<u32>,
) -> Result<bool, sp_runtime::DispatchError> {
	<Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(&proof(), s, version)
}

fn verify_unshield(
	s: &UnshieldStatement,
	version: Option<u32>,
) -> Result<bool, sp_runtime::DispatchError> {
	<Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(&proof(), s, version)
}

fn shield() -> ShieldStatement {
	ShieldStatement {
		commitment: [0x05; 32],
		value: 1000,
		asset_id: 0,
	}
}

fn verify_shield(
	s: &ShieldStatement,
	version: Option<u32>,
) -> Result<bool, sp_runtime::DispatchError> {
	<Pallet<Test> as ZkVerifierPort>::verify_shield_proof(&proof(), s, version)
}

// ── verify_transfer_proof ─────────────────────────────────────────────────

#[test]
fn transfer_empty_proof_is_rejected() {
	new_test_ext().execute_with(|| {
		assert_err!(
			<Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(&[], &transfer(), Some(1)),
			Error::<Test>::EmptyProof
		);
	});
}

#[test]
fn transfer_without_an_active_version_is_circuit_not_found() {
	new_test_ext().execute_with(|| {
		assert_err!(
			verify_transfer(&transfer(), None),
			Error::<Test>::CircuitNotFound
		);
	});
}

#[test]
fn transfer_unknown_explicit_version_is_unsupported() {
	new_test_ext().execute_with(|| {
		assert_err!(
			verify_transfer(&transfer(), Some(99)),
			Error::<Test>::UnsupportedCircuitVersion
		);
	});
}

/// A base key in storage — never registrable, but left by an older runtime
/// or a raw storage write — verifies nothing, active or named.
#[test]
fn transfer_verifies_under_the_memo_bound_key_only() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(
			CircuitId::TRANSFER,
			2,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::TRANSFER, 1);
		assert_eq!(verify_transfer(&transfer(), None), Ok(false));
		assert_eq!(verify_transfer(&transfer(), Some(1)), Ok(false));
		assert_eq!(verify_transfer(&transfer(), Some(2)), Ok(true));
	});
}

/// Every key arity, registered side by side as v1, v2 and v3.
fn insert_all_transfer_keys() {
	insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
	insert_vk(
		CircuitId::TRANSFER,
		2,
		TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
	);
	insert_vk(
		CircuitId::TRANSFER,
		3,
		TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS + CROSS_TREE_INPUTS,
	);
	activate(CircuitId::TRANSFER, 3);
}

#[test]
fn a_same_tree_transfer_verifies_under_every_admitted_key() {
	new_test_ext().execute_with(|| {
		insert_all_transfer_keys();
		assert_eq!(verify_transfer(&transfer(), Some(1)), Ok(false));
		for version in 2..=3 {
			assert_eq!(verify_transfer(&transfer(), Some(version)), Ok(true));
		}
	});
}

#[test]
fn only_the_cross_tree_key_verifies_a_spend_across_two_trees() {
	new_test_ext().execute_with(|| {
		insert_all_transfer_keys();
		let across = TransferStatement {
			merkle_roots: [[0x03; 32], [0x07; 32]],
			..transfer()
		};
		assert_eq!(verify_transfer(&across, Some(3)), Ok(true));
		assert_eq!(verify_transfer(&across, Some(2)), Ok(false));
		assert_eq!(verify_transfer(&across, Some(1)), Ok(false));
	});
}

#[test]
fn transfer_with_one_input_does_not_fit_the_two_input_key() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let s = TransferStatement {
			nullifiers: NULLIFIERS[..1].to_vec(),
			commitments: COMMITMENTS[..1].to_vec(),
			..transfer()
		};
		assert_eq!(verify_transfer(&s, None), Ok(false));
	});
}

#[test]
fn transfer_nullifier_commitment_count_mismatch_is_rejected() {
	new_test_ext().execute_with(|| {
		let s = TransferStatement {
			nullifiers: NULLIFIERS[..1].to_vec(),
			..transfer()
		};
		assert_err!(
			verify_transfer(&s, Some(1)),
			Error::<Test>::InvalidPublicInputs
		);
	});
}

#[test]
fn a_retired_version_is_unsupported_and_does_not_fall_back() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		RetiredVersions::<Test>::insert(CircuitId::TRANSFER, 2, ());

		assert!(!<Pallet<Test> as ZkVerifierPort>::is_supported_version(
			CircuitId::TRANSFER.0,
			2
		));
		assert_err!(
			verify_transfer(&transfer(), Some(2)),
			Error::<Test>::UnsupportedCircuitVersion
		);
	});
}

// ── verify_unshield_proof ─────────────────────────────────────────────────

#[test]
fn unshield_empty_proof_is_rejected() {
	new_test_ext().execute_with(|| {
		assert_err!(
			<Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(&[], &unshield(), Some(1)),
			Error::<Test>::EmptyProof
		);
	});
}

#[test]
fn unshield_without_an_active_version_is_circuit_not_found() {
	new_test_ext().execute_with(|| {
		assert_err!(
			verify_unshield(&unshield(), None),
			Error::<Test>::CircuitNotFound
		);
	});
}

#[test]
fn unshield_unknown_explicit_version_is_unsupported() {
	new_test_ext().execute_with(|| {
		assert_err!(
			verify_unshield(&unshield(), Some(99)),
			Error::<Test>::UnsupportedCircuitVersion
		);
	});
}

/// A base key in storage — never registrable, but left by an older runtime
/// or a raw storage write — verifies nothing, active or named.
#[test]
fn unshield_verifies_under_the_memo_bound_key_only() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS);
		insert_vk(
			CircuitId::UNSHIELD,
			2,
			UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::UNSHIELD, 1);
		assert_eq!(verify_unshield(&unshield(), None), Ok(false));
		assert_eq!(verify_unshield(&unshield(), Some(1)), Ok(false));
		assert_eq!(verify_unshield(&unshield(), Some(2)), Ok(true));
	});
}

#[test]
fn unshield_under_a_key_of_foreign_arity_fails() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS + 2);
		activate(CircuitId::UNSHIELD, 1);
		assert_eq!(verify_unshield(&unshield(), None), Ok(false));
	});
}

// ── verify_shield_proof ───────────────────────────────────────────────────

#[test]
fn shield_empty_proof_is_rejected() {
	new_test_ext().execute_with(|| {
		assert_err!(
			<Pallet<Test> as ZkVerifierPort>::verify_shield_proof(&[], &shield(), Some(1)),
			Error::<Test>::EmptyProof
		);
	});
}

#[test]
fn shield_without_an_active_version_is_circuit_not_found() {
	new_test_ext().execute_with(|| {
		assert_err!(
			verify_shield(&shield(), None),
			Error::<Test>::CircuitNotFound
		);
	});
}

#[test]
fn shield_verifies_under_its_three_input_key() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::SHIELD, 1, SHIELD_PUBLIC_INPUTS);
		activate(CircuitId::SHIELD, 1);
		assert_eq!(verify_shield(&shield(), None), Ok(true));
	});
}

#[test]
fn shield_under_a_key_of_foreign_arity_fails() {
	new_test_ext().execute_with(|| {
		insert_vk(
			CircuitId::SHIELD,
			1,
			SHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::SHIELD, 1);
		assert_eq!(verify_shield(&shield(), None), Ok(false));
	});
}

#[test]
fn shield_under_a_retired_or_unregistered_version_is_unsupported() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::SHIELD, 1, SHIELD_PUBLIC_INPUTS);
		insert_vk(CircuitId::SHIELD, 2, SHIELD_PUBLIC_INPUTS);
		activate(CircuitId::SHIELD, 2);
		RetiredVersions::<Test>::insert(CircuitId::SHIELD, 1, ());

		// A retired version does not fall back to the active one.
		assert_err!(
			verify_shield(&shield(), Some(1)),
			Error::<Test>::UnsupportedCircuitVersion
		);
		assert_err!(
			verify_shield(&shield(), Some(3)),
			Error::<Test>::UnsupportedCircuitVersion
		);
		assert_eq!(verify_shield(&shield(), Some(2)), Ok(true));
	});
}

// ── is_supported_version ──────────────────────────────────────────────────

#[test]
fn is_supported_version_reflects_registered_keys() {
	new_test_ext().execute_with(|| {
		let supported =
			|id: CircuitId, v| <Pallet<Test> as ZkVerifierPort>::is_supported_version(id.0, v);
		assert!(!supported(CircuitId::TRANSFER, 1));
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		assert!(supported(CircuitId::TRANSFER, 1));
		assert!(!supported(CircuitId::TRANSFER, 2));
		assert!(!supported(CircuitId::UNSHIELD, 1));
	});
}

#[test]
fn verification_weight_covers_the_largest_spend_layout() {
	use crate::weights::WeightInfo;
	assert_eq!(MAX_SPEND_PUBLIC_INPUTS, 9);
	use frame_support::traits::Get;
	assert_eq!(
		<Pallet<Test> as ZkVerifierPort>::verification_weight(),
		<Test as crate::Config>::WeightInfo::verify_proof(MAX_SPEND_PUBLIC_INPUTS).saturating_add(
			<<Test as frame_system::Config>::DbWeight as Get<
				frame_support::weights::RuntimeDbWeight,
			>>::get()
			.reads(1)
		)
	);
}
