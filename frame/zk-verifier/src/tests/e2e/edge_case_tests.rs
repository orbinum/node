//! Edge case tests for pallet-zk-verifier
//!
//! Tests for boundary conditions and uncommon scenarios

use crate::{
	VerificationKeys,
	mock::*,
	types::{CircuitId, ProofSystem},
};
use frame_support::{BoundedVec, assert_ok, pallet_prelude::ConstU32};

// ============================================================================
// Helper Functions
// ============================================================================

fn sample_verification_key() -> Vec<u8> {
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[1u8; 64]);
	vk.extend_from_slice(&[2u8; 128]);
	vk.extend_from_slice(&[3u8; 128]);
	vk.extend_from_slice(&[4u8; 128]);
	vk.extend_from_slice(&[5u8; 64]);
	vk
}

fn sample_proof() -> Vec<u8> {
	let mut proof = Vec::with_capacity(256);
	proof.extend_from_slice(&[10u8; 64]);
	proof.extend_from_slice(&[11u8; 128]);
	proof.extend_from_slice(&[12u8; 64]);
	proof
}

// ============================================================================
// Public Inputs Edge Cases
// ============================================================================

#[test]
fn verify_proof_with_zero_public_inputs_allowed_in_test_mode() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");

		// Empty public inputs
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![].try_into().unwrap();

		// In test mode, verifier bypasses validation and succeeds
		// In production, this would be rejected by domain logic
		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));
	});
}

#[test]
fn verify_proof_with_single_public_input() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));
	});
}

#[test]
fn verify_proof_with_maximum_public_inputs() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");

		// Create exactly 16 inputs (MaxPublicInputs)
		let mut inputs = vec![];
		for i in 0..16 {
			inputs.push([i as u8; 32].to_vec().try_into().unwrap());
		}
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = inputs.try_into().unwrap();

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));
	});
}

#[test]
fn verify_proof_rejects_oversized_public_input() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk.clone(),
			ProofSystem::Groth16,
		));

		let proof = sample_proof();
		let _proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");

		// Input larger than 32 bytes should fail to convert
		let large_input = vec![1u8; 33];
		let result: Result<BoundedVec<u8, ConstU32<32>>, _> = large_input.try_into();

		assert!(result.is_err());
	});
}

#[test]
fn verify_proof_with_all_zero_inputs() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[0u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));
	});
}

#[test]
fn verify_proof_with_all_max_inputs() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[0xFFu8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));
	});
}

// ============================================================================
// Proof Size Edge Cases
// ============================================================================

#[test]
fn register_vk_at_minimum_size() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = vec![1u8; 512]; // Minimum valid size

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));
	});
}

#[test]
fn register_vk_at_maximum_size() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = vec![1u8; 8192]; // MaxVerificationKeySize

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));
	});
}

#[test]
fn verify_with_minimum_proof_size() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = vec![1u8; 1]; // Very small proof
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		// Should succeed in test mode even with tiny proof
		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));
	});
}

#[test]
fn verify_with_maximum_proof_size() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = vec![1u8; 256]; // MaxProofSize
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));
	});
}

// ============================================================================
// Circuit ID Edge Cases
// ============================================================================

#[test]
fn register_circuit_id_zero() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(0);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		assert!(VerificationKeys::<Test>::contains_key(circuit_id, 1));
	});
}

#[test]
fn register_circuit_id_max_u32() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(u32::MAX);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		assert!(VerificationKeys::<Test>::contains_key(circuit_id, 1));
	});
}

// ============================================================================
// Concurrent Operations Edge Cases
// ============================================================================

#[test]
fn multiple_users_can_verify_simultaneously() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// User 1 verifies
		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.clone().try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded.clone()
		));

		// User 2 verifies
		let proof_bounded2: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(2),
			circuit_id,
			proof_bounded2,
			inputs_bounded
		));
	});
}

#[test]
fn register_remove_register_same_circuit() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk1 = sample_verification_key();
		let mut vk2 = sample_verification_key();
		vk2[0] = 99;

		// Register
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk1.clone(),
			ProofSystem::Groth16,
		));

		// Remove
		assert_ok!(ZkVerifier::remove_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1
		));

		// Register again with different VK
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk2.clone(),
			ProofSystem::Groth16,
		));

		// Verify new VK is stored
		let stored = VerificationKeys::<Test>::get(circuit_id, 1).unwrap();
		assert_eq!(stored.key_data.to_vec(), vk2);
	});
}

// ============================================================================
// Block Boundary Edge Cases
// ============================================================================

#[test]
fn operations_across_multiple_blocks() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		// Block 1: Register
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk,
			ProofSystem::Groth16,
		));

		run_to_block(5);

		// Block 5: Verify
		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));

		run_to_block(10);

		// Block 10: Remove
		assert_ok!(ZkVerifier::remove_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1
		));

		assert!(!VerificationKeys::<Test>::contains_key(circuit_id, 1));
	});
}
