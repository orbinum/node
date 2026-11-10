//! The `verify_proof` extrinsic.

use crate::tests::util::*;
use crate::{CircuitId, Error, Event, tests::mock::*};
use frame_support::{BoundedVec, assert_err, assert_noop, assert_ok, traits::ConstU32};
use orbinum_zk_verifier::{MEMO_HASH_INPUTS, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS};

#[test]
fn verify_proof_requires_signed_origin() {
	new_test_ext().execute_with(|| {
		assert_err!(
			ZkVerifier::verify_proof(
				root().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				one_public_input()
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn verify_proof_weight_grows_with_inputs() {
	use crate::weights::WeightInfo;
	type W = crate::weights::SubstrateWeight<Test>;
	assert!(W::verify_proof(8).ref_time() > W::verify_proof(1).ref_time());
	assert!(W::verify_proof(32).ref_time() > W::verify_proof(8).ref_time());
}

#[test]
fn verify_proof_no_active_version_returns_circuit_not_found() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				one_public_input()
			),
			Error::<Test>::CircuitNotFound
		);
	});
}

#[test]
fn verify_proof_missing_vk_returns_not_found() {
	new_test_ext().execute_with(|| {
		activate(CircuitId::TRANSFER, 99);
		assert_noop!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				one_public_input()
			),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn verify_proof_empty_proof_returns_empty_proof_error() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let empty: Proof = BoundedVec::default();
		assert_noop!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				empty,
				one_public_input()
			),
			Error::<Test>::EmptyProof
		);
	});
}

#[test]
fn verify_proof_empty_public_inputs_returns_error() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let no_inputs: PublicInputs = BoundedVec::default();
		assert_noop!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				no_inputs
			),
			Error::<Test>::EmptyPublicInputs
		);
	});
}

#[test]
fn verify_proof_happy_path_emits_proof_verified_event() {
	// In test cfg, do_verify always returns true.
	new_test_ext().execute_with(|| {
		insert_vk(
			CircuitId::TRANSFER,
			1,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::TRANSFER, 1);
		let inputs: PublicInputs = (0..TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS)
			.map(|_| vec![0x02u8; 32].try_into().unwrap())
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();
		assert_ok!(ZkVerifier::verify_proof(
			signed().into(),
			CircuitId::TRANSFER,
			proof_bytes(),
			inputs,
		));
		assert!(has_event(Event::ProofVerified {
			circuit_id: CircuitId::TRANSFER,
			version: 1
		}));
	});
}

#[test]
fn verify_proof_rejects_short_public_input() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS);
		activate(CircuitId::UNSHIELD, 1);
		let short: BoundedVec<u8, ConstU32<32>> = vec![0xFFu8; 4].try_into().unwrap();
		let inputs: PublicInputs = vec![short].try_into().unwrap();
		assert_noop!(
			ZkVerifier::verify_proof(signed().into(), CircuitId::UNSHIELD, proof_bytes(), inputs),
			Error::<Test>::InvalidPublicInputs
		);
	});
}
