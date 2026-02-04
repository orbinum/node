//! Tests for Statistics tracking
//!
//! These tests verify that VerificationStats storage is updated correctly

use crate::{
	Error, VerificationStats,
	mock::*,
	types::{CircuitId, ProofSystem},
};
use frame_support::{BoundedVec, assert_noop, assert_ok, pallet_prelude::ConstU32};

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

fn setup_circuit(circuit_id: CircuitId) {
	let vk = sample_verification_key();
	assert_ok!(ZkVerifier::register_verification_key(
		RuntimeOrigin::root(),
		circuit_id,
		1,
		vk,
		ProofSystem::Groth16,
	));
}

// ============================================================================
// Initial State Tests
// ============================================================================

#[test]
fn statistics_start_at_zero() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		setup_circuit(circuit_id);

		let stats = VerificationStats::<Test>::get(circuit_id, 1);
		assert_eq!(stats.total_verifications, 0);
		assert_eq!(stats.successful_verifications, 0);
		assert_eq!(stats.failed_verifications, 0);
	});
}

// ============================================================================
// Verification Success Tests
// ============================================================================

#[test]
fn statistics_increment_on_successful_verification() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		setup_circuit(circuit_id);

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		// Verify proof
		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));

		// Check statistics
		let stats = VerificationStats::<Test>::get(circuit_id, 1);
		assert_eq!(stats.total_verifications, 1);
		assert_eq!(stats.successful_verifications, 1);
		assert_eq!(stats.failed_verifications, 0);
	});
}

#[test]
fn statistics_increment_on_multiple_verifications() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		setup_circuit(circuit_id);

		// Perform 3 verifications
		for _ in 0..3 {
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
		}

		// Check statistics
		let stats = VerificationStats::<Test>::get(circuit_id, 1);
		assert_eq!(stats.total_verifications, 3);
		assert_eq!(stats.successful_verifications, 3);
		assert_eq!(stats.failed_verifications, 0);
	});
}

// ============================================================================
// Verification Failure Tests
// ============================================================================

#[test]
fn statistics_track_circuit_not_found() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(999);
		// Don't setup circuit

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		assert_noop!(
			ZkVerifier::verify_proof(
				RuntimeOrigin::signed(1),
				circuit_id,
				proof_bounded,
				inputs_bounded
			),
			Error::<Test>::CircuitNotFound
		);

		// Statistics should remain at zero since circuit doesn't exist
		let stats = VerificationStats::<Test>::get(circuit_id, 1);
		assert_eq!(stats.total_verifications, 0);
		assert_eq!(stats.successful_verifications, 0);
		assert_eq!(stats.failed_verifications, 0);
	});
}

#[test]
fn statistics_track_invalid_proof() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		setup_circuit(circuit_id);

		let proof = vec![]; // Empty proof
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		assert_noop!(
			ZkVerifier::verify_proof(
				RuntimeOrigin::signed(1),
				circuit_id,
				proof_bounded,
				inputs_bounded
			),
			Error::<Test>::EmptyProof
		);

		// Statistics should not increment on validation errors
		let stats = VerificationStats::<Test>::get(circuit_id, 1);
		assert_eq!(stats.total_verifications, 0);
	});
}

// ============================================================================
// Per-Circuit Statistics Tests
// ============================================================================

#[test]
fn statistics_are_per_circuit() {
	new_test_ext().execute_with(|| {
		let circuit_id_1 = CircuitId(1);
		let circuit_id_2 = CircuitId(2);

		setup_circuit(circuit_id_1);
		setup_circuit(circuit_id_2);

		// Verify proof for circuit 1
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
			circuit_id_1,
			proof_bounded,
			inputs_bounded.clone()
		));

		// Verify proof for circuit 2 (twice)
		for _ in 0..2 {
			let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
				proof.clone().try_into().expect("proof too large");

			assert_ok!(ZkVerifier::verify_proof(
				RuntimeOrigin::signed(1),
				circuit_id_2,
				proof_bounded,
				inputs_bounded.clone()
			));
		}

		// Check circuit 1 stats
		let stats1 = VerificationStats::<Test>::get(circuit_id_1, 1);
		assert_eq!(stats1.total_verifications, 1);
		assert_eq!(stats1.successful_verifications, 1);

		// Check circuit 2 stats
		let stats2 = VerificationStats::<Test>::get(circuit_id_2, 1);
		assert_eq!(stats2.total_verifications, 2);
		assert_eq!(stats2.successful_verifications, 2);
	});
}

// ============================================================================
// Statistics Persistence Tests
// ============================================================================

#[test]
fn statistics_persist_across_blocks() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		setup_circuit(circuit_id);

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		// Verify in block 1
		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded.clone(),
			inputs_bounded.clone()
		));

		// Advance to block 10
		run_to_block(10);

		// Verify again
		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));

		// Statistics should accumulate
		let stats = VerificationStats::<Test>::get(circuit_id, 1);
		assert_eq!(stats.total_verifications, 2);
		assert_eq!(stats.successful_verifications, 2);
	});
}

// ============================================================================
// Statistics After VK Removal Tests
// ============================================================================

#[test]
fn statistics_remain_after_vk_removal() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		setup_circuit(circuit_id);

		let proof = sample_proof();
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		// Verify proof
		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id,
			proof_bounded,
			inputs_bounded
		));

		// Remove VK
		assert_ok!(ZkVerifier::remove_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1
		));

		// Statistics should still exist
		let stats = VerificationStats::<Test>::get(circuit_id, 1);
		assert_eq!(stats.total_verifications, 1);
		assert_eq!(stats.successful_verifications, 1);
	});
}

// ============================================================================
// High Volume Tests
// ============================================================================

#[test]
fn statistics_handle_high_volume() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		setup_circuit(circuit_id);

		// Perform 100 verifications
		for _ in 0..100 {
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
		}

		let stats = VerificationStats::<Test>::get(circuit_id, 1);
		assert_eq!(stats.total_verifications, 100);
		assert_eq!(stats.successful_verifications, 100);
		assert_eq!(stats.failed_verifications, 0);
	});
}
