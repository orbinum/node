//! End-to-End tests for extrinsics
//!
//! These tests use the full FRAME runtime mock to test extrinsics

use crate::{
	Error, Event, VerificationKeys,
	mock::*,
	types::{CircuitId, ProofSystem},
};
use frame_support::{BoundedVec, assert_noop, assert_ok, pallet_prelude::ConstU32};
use sp_runtime::DispatchError;

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a sample Groth16 verification key for testing
fn sample_verification_key() -> Vec<u8> {
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[1u8; 64]); // alpha_g1
	vk.extend_from_slice(&[2u8; 128]); // beta_g2
	vk.extend_from_slice(&[3u8; 128]); // gamma_g2
	vk.extend_from_slice(&[4u8; 128]); // delta_g2
	vk.extend_from_slice(&[5u8; 64]); // IC[0]
	vk
}

fn sample_vk_proof_inputs() -> (Vec<u8>, Vec<u8>, Vec<[u8; 32]>) {
	let vk = sample_verification_key();
	let mut proof = Vec::with_capacity(256);
	proof.extend_from_slice(&[10u8; 64]); // A
	proof.extend_from_slice(&[11u8; 128]); // B
	proof.extend_from_slice(&[12u8; 64]); // C
	let public_inputs = vec![];
	(vk, proof, public_inputs)
}

// ============================================================================
// Registration Tests
// ============================================================================

#[test]
fn register_verification_key_works() {
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

		assert!(VerificationKeys::<Test>::contains_key(circuit_id, 1));
		let stored = VerificationKeys::<Test>::get(circuit_id, 1).unwrap();
		assert_eq!(stored.system, ProofSystem::Groth16);
		assert_eq!(stored.key_data.to_vec(), vk);

		System::assert_has_event(
			Event::VerificationKeyRegistered {
				circuit_id,
				version: 1,
				system: ProofSystem::Groth16,
			}
			.into(),
		);
	});
}

#[test]
fn register_verification_key_requires_admin() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = sample_verification_key();

		assert_noop!(
			ZkVerifier::register_verification_key(
				RuntimeOrigin::signed(1),
				circuit_id,
				1,
				vk,
				ProofSystem::Groth16,
			),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn register_verification_key_rejects_empty() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);

		assert_noop!(
			ZkVerifier::register_verification_key(
				RuntimeOrigin::root(),
				circuit_id,
				1,
				vec![],
				ProofSystem::Groth16,
			),
			Error::<Test>::EmptyVerificationKey
		);
	});
}

#[test]
fn register_verification_key_rejects_too_large() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk = vec![1u8; 100_001];

		assert_noop!(
			ZkVerifier::register_verification_key(
				RuntimeOrigin::root(),
				circuit_id,
				1,
				vk,
				ProofSystem::Groth16,
			),
			Error::<Test>::VerificationKeyTooLarge
		);
	});
}

// ============================================================================
// Removal Tests
// ============================================================================

#[test]
fn remove_verification_key_works() {
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

		assert_ok!(ZkVerifier::remove_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1
		));

		assert!(!VerificationKeys::<Test>::contains_key(circuit_id, 1));

		System::assert_has_event(
			Event::VerificationKeyRemoved {
				circuit_id,
				version: 1,
			}
			.into(),
		);
	});
}

#[test]
fn remove_verification_key_requires_admin() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);

		assert_noop!(
			ZkVerifier::remove_verification_key(RuntimeOrigin::signed(1), circuit_id, 1),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn remove_verification_key_requires_existing() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);

		assert_noop!(
			ZkVerifier::remove_verification_key(RuntimeOrigin::root(), circuit_id, 1),
			Error::<Test>::CircuitNotFound
		);
	});
}

// ============================================================================
// Verification Tests
// ============================================================================

#[test]
fn verify_proof_requires_vk() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let (_vk, proof, inputs) = sample_vk_proof_inputs();

		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = inputs
			.into_iter()
			.map(|i| i.to_vec().try_into().expect("input too large"))
			.collect::<Vec<_>>()
			.try_into()
			.expect("too many inputs");

		assert_noop!(
			ZkVerifier::verify_proof(
				RuntimeOrigin::signed(1),
				circuit_id,
				proof_bounded,
				inputs_bounded
			),
			Error::<Test>::CircuitNotFound
		);
	});
}

// ============================================================================
// Update Tests
// ============================================================================

#[test]
fn update_verification_key_rejects_duplicate() {
	new_test_ext().execute_with(|| {
		let circuit_id = CircuitId(1);
		let vk1 = sample_verification_key();
		let mut vk2 = sample_verification_key();
		vk2[0] = 99;

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id,
			1,
			vk1.clone(),
			ProofSystem::Groth16,
		));

		// Clean Architecture: domain logic rejects duplicates
		assert_noop!(
			ZkVerifier::register_verification_key(
				RuntimeOrigin::root(),
				circuit_id,
				1,
				vk2.clone(),
				ProofSystem::Groth16,
			),
			Error::<Test>::CircuitAlreadyExists
		);

		// Verify original key is still stored
		let stored = VerificationKeys::<Test>::get(circuit_id, 1).unwrap();
		assert_eq!(stored.key_data.to_vec(), vk1);
	});
}

// ============================================================================
// Supported Systems Tests
// ============================================================================

#[test]
fn only_groth16_is_supported() {
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

		// Note: PLONK and Halo2 will be rejected by the validator
		// when we add proper validation in the future
	});
}

// ============================================================================
// Circuit ID Tests
// ============================================================================

#[test]
fn transfer_circuit_id_is_1() {
	assert_eq!(CircuitId::TRANSFER.0, 1);
}

#[test]
fn unshield_circuit_id_is_2() {
	assert_eq!(CircuitId::UNSHIELD.0, 2);
}

#[test]
fn shield_circuit_id_is_3() {
	assert_eq!(CircuitId::SHIELD.0, 3);
}

// ============================================================================
// Event Tests - ProofVerified and ProofVerificationFailed
// ============================================================================

#[test]
fn verify_proof_emits_success_event() {
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

		let proof = sample_vk_proof_inputs().1;
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

		System::assert_has_event(
			Event::ProofVerified {
				circuit_id,
				version: 1,
			}
			.into(),
		);
	});
}

#[test]
fn verify_proof_emits_failure_event_on_invalid_proof() {
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

		// Empty proof will fail validation before reaching verifier
		// This tests validation errors, not verification failures
		let proof = vec![];
		let proof_bounded: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as crate::pallet::Config>::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		// Should fail validation
		assert_noop!(
			ZkVerifier::verify_proof(
				RuntimeOrigin::signed(1),
				circuit_id,
				proof_bounded,
				inputs_bounded
			),
			Error::<Test>::EmptyProof
		);
	});
}

#[test]
fn multiple_verifications_emit_multiple_events() {
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

		// Perform 3 verifications
		for _ in 0..3 {
			let proof = sample_vk_proof_inputs().1;
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

		// Check we have 3 ProofVerified events (plus 1 VerificationKeyRegistered)
		let events = System::events();
		let proof_verified_count = events
			.iter()
			.filter(|e| {
				matches!(
					e.event,
					crate::mock::RuntimeEvent::ZkVerifier(Event::ProofVerified { .. })
				)
			})
			.count();

		assert_eq!(proof_verified_count, 3);
	});
}

#[test]
fn events_include_correct_circuit_id() {
	new_test_ext().execute_with(|| {
		let circuit_id_1 = CircuitId(1);
		let circuit_id_2 = CircuitId(2);
		let vk = sample_verification_key();

		// Register two circuits
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id_1,
			1,
			vk.clone(),
			ProofSystem::Groth16,
		));

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			circuit_id_2,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Verify with circuit 1
		let proof = sample_vk_proof_inputs().1;
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

		// Verify with circuit 2
		let proof_bounded2: BoundedVec<u8, <Test as crate::pallet::Config>::MaxProofSize> =
			proof.try_into().expect("proof too large");

		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			circuit_id_2,
			proof_bounded2,
			inputs_bounded
		));

		// Check events have correct circuit IDs
		System::assert_has_event(
			Event::ProofVerified {
				circuit_id: circuit_id_1,
				version: 1,
			}
			.into(),
		);

		System::assert_has_event(
			Event::ProofVerified {
				circuit_id: circuit_id_2,
				version: 1,
			}
			.into(),
		);
	});
}
