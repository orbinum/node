//! Tests for ZkVerifierPort trait - Public API integration tests
//!
//! These tests verify that the ZkVerifierPort trait implementation works correctly.
//! This trait is the public interface that other pallets should use to verify ZK proofs.

use crate::{
	ZkVerifierPort,
	mock::*,
	types::{CircuitId, ProofSystem},
};
use frame_support::assert_ok;

// ============================================================================
// Helper Functions
// ============================================================================

fn setup_transfer_circuit() -> Vec<u8> {
	// Crear VK de 512 bytes para el circuito de transferencia
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[1u8; 64]); // alpha_g1
	vk.extend_from_slice(&[2u8; 128]); // beta_g2
	vk.extend_from_slice(&[3u8; 128]); // gamma_g2
	vk.extend_from_slice(&[4u8; 128]); // delta_g2
	vk.extend_from_slice(&[5u8; 64]); // gamma_abc_g1

	assert_ok!(ZkVerifier::register_verification_key(
		RuntimeOrigin::root(),
		CircuitId::TRANSFER,
		1,
		vk.clone(),
		ProofSystem::Groth16,
	));

	vk
}

fn setup_unshield_circuit() -> Vec<u8> {
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[6u8; 64]);
	vk.extend_from_slice(&[7u8; 128]);
	vk.extend_from_slice(&[8u8; 128]);
	vk.extend_from_slice(&[9u8; 128]);
	vk.extend_from_slice(&[10u8; 64]);

	assert_ok!(ZkVerifier::register_verification_key(
		RuntimeOrigin::root(),
		CircuitId::UNSHIELD,
		1,
		vk.clone(),
		ProofSystem::Groth16,
	));

	vk
}

fn sample_proof() -> Vec<u8> {
	let mut proof = Vec::with_capacity(256);
	proof.extend_from_slice(&[10u8; 64]); // proof.a
	proof.extend_from_slice(&[11u8; 128]); // proof.b
	proof.extend_from_slice(&[12u8; 64]); // proof.c
	proof
}

// ============================================================================
// ZkVerifierPort::verify_transfer_proof Tests
// ============================================================================

#[test]
fn port_verify_transfer_proof_works() {
	new_test_ext().execute_with(|| {
		setup_transfer_circuit();

		let proof = sample_proof();
		let merkle_root = [1u8; 32];
		let nullifiers = [[2u8; 32], [3u8; 32]];
		let commitments = [[4u8; 32], [5u8; 32]];

		// En test mode, el verifier bypasea la verificación real
		let result = ZkVerifier::verify_transfer_proof(
			&proof,
			&merkle_root,
			&nullifiers,
			&commitments,
			None,
		);

		assert_ok!(result);
		assert!(result.unwrap());
	});
}

#[test]
fn port_verify_transfer_proof_fails_without_vk() {
	new_test_ext().execute_with(|| {
		// No registramos el VK

		let proof = sample_proof();
		let merkle_root = [1u8; 32];
		let nullifiers = [[2u8; 32], [3u8; 32]];
		let commitments = [[4u8; 32], [5u8; 32]];

		let result = ZkVerifier::verify_transfer_proof(
			&proof,
			&merkle_root,
			&nullifiers,
			&commitments,
			None,
		);

		assert!(result.is_err());
	});
}

#[test]
fn port_verify_transfer_proof_with_empty_proof() {
	new_test_ext().execute_with(|| {
		setup_transfer_circuit();

		let proof = Vec::new(); // Prueba vacía
		let merkle_root = [1u8; 32];
		let nullifiers = [[2u8; 32], [3u8; 32]];
		let commitments = [[4u8; 32], [5u8; 32]];

		let result = ZkVerifier::verify_transfer_proof(
			&proof,
			&merkle_root,
			&nullifiers,
			&commitments,
			None,
		);

		assert!(result.is_err());
	});
}

#[test]
fn port_verify_transfer_proof_with_single_nullifier() {
	new_test_ext().execute_with(|| {
		setup_transfer_circuit();

		let proof = sample_proof();
		let merkle_root = [1u8; 32];
		let nullifiers = [[2u8; 32]]; // Solo un nullifier
		let commitments = [[4u8; 32], [5u8; 32]];

		let result = ZkVerifier::verify_transfer_proof(
			&proof,
			&merkle_root,
			&nullifiers,
			&commitments,
			None,
		);

		// Debería funcionar con cualquier número de nullifiers
		assert_ok!(result);
	});
}

#[test]
fn port_verify_transfer_proof_with_multiple_nullifiers_and_commitments() {
	new_test_ext().execute_with(|| {
		setup_transfer_circuit();

		let proof = sample_proof();
		let merkle_root = [1u8; 32];
		let nullifiers = [[2u8; 32], [3u8; 32], [10u8; 32]]; // 3 nullifiers
		let commitments = [[4u8; 32], [5u8; 32], [6u8; 32]]; // 3 commitments

		let result = ZkVerifier::verify_transfer_proof(
			&proof,
			&merkle_root,
			&nullifiers,
			&commitments,
			None,
		);

		assert_ok!(result);
	});
}

// ============================================================================
// ZkVerifierPort::verify_unshield_proof Tests
// ============================================================================

#[test]
fn port_verify_unshield_proof_works() {
	new_test_ext().execute_with(|| {
		setup_unshield_circuit();

		let proof = sample_proof();
		let merkle_root = [1u8; 32];
		let nullifier = [2u8; 32];
		let amount = 1_000_000u128;

		let result =
			ZkVerifier::verify_unshield_proof(&proof, &merkle_root, &nullifier, amount, None);

		assert_ok!(result);
		assert!(result.unwrap());
	});
}

#[test]
fn port_verify_unshield_proof_fails_without_vk() {
	new_test_ext().execute_with(|| {
		// No registramos el VK

		let proof = sample_proof();
		let merkle_root = [1u8; 32];
		let nullifier = [2u8; 32];
		let amount = 1_000_000u128;

		let result =
			ZkVerifier::verify_unshield_proof(&proof, &merkle_root, &nullifier, amount, None);

		assert!(result.is_err());
	});
}

#[test]
fn port_verify_unshield_proof_with_empty_proof() {
	new_test_ext().execute_with(|| {
		setup_unshield_circuit();

		let proof = Vec::new(); // Prueba vacía
		let merkle_root = [1u8; 32];
		let nullifier = [2u8; 32];
		let amount = 1_000_000u128;

		let result =
			ZkVerifier::verify_unshield_proof(&proof, &merkle_root, &nullifier, amount, None);

		assert!(result.is_err());
	});
}

#[test]
fn port_verify_unshield_proof_with_zero_amount() {
	new_test_ext().execute_with(|| {
		setup_unshield_circuit();

		let proof = sample_proof();
		let merkle_root = [1u8; 32];
		let nullifier = [2u8; 32];
		let amount = 0u128;

		let result =
			ZkVerifier::verify_unshield_proof(&proof, &merkle_root, &nullifier, amount, None);

		// En test mode, funciona incluso con amount=0
		assert_ok!(result);
	});
}

#[test]
fn port_verify_unshield_proof_with_max_amount() {
	new_test_ext().execute_with(|| {
		setup_unshield_circuit();

		let proof = sample_proof();
		let merkle_root = [1u8; 32];
		let nullifier = [2u8; 32];
		let amount = u128::MAX;

		let result =
			ZkVerifier::verify_unshield_proof(&proof, &merkle_root, &nullifier, amount, None);

		assert_ok!(result);
	});
}

// ============================================================================
// Cross-Circuit Tests
// ============================================================================

#[test]
fn port_can_verify_multiple_circuit_types() {
	new_test_ext().execute_with(|| {
		setup_transfer_circuit();
		setup_unshield_circuit();

		let proof = sample_proof();

		// Verificar transfer
		let result1 =
			ZkVerifier::verify_transfer_proof(&proof, &[1u8; 32], &[[2u8; 32]], &[[3u8; 32]], None);
		assert_ok!(result1);

		// Verificar unshield
		let result2 =
			ZkVerifier::verify_unshield_proof(&proof, &[4u8; 32], &[5u8; 32], 100_000u128, None);
		assert_ok!(result2);
	});
}

#[test]
fn port_maintains_independent_statistics() {
	new_test_ext().execute_with(|| {
		setup_transfer_circuit();
		setup_unshield_circuit();

		let proof = sample_proof();

		// Verificar transfer 2 veces
		for _ in 0..2 {
			let _ = ZkVerifier::verify_transfer_proof(
				&proof,
				&[1u8; 32],
				&[[2u8; 32]],
				&[[3u8; 32]],
				None,
			);
		}

		// Verificar unshield 3 veces
		for _ in 0..3 {
			let _ = ZkVerifier::verify_unshield_proof(
				&proof,
				&[4u8; 32],
				&[5u8; 32],
				100_000u128,
				None,
			);
		}

		// Las estadísticas deberían ser independientes
		let transfer_stats = crate::VerificationStats::<Test>::get(CircuitId::TRANSFER, 1);
		let unshield_stats = crate::VerificationStats::<Test>::get(CircuitId::UNSHIELD, 1);

		assert_eq!(transfer_stats.total_verifications, 2);
		assert_eq!(unshield_stats.total_verifications, 3);
	});
}
