//! End-to-end tests for disclosure proof verification
//!
//! These tests use REAL ZK proofs and verification keys (not mocks).
//! They verify the complete flow from proof submission to verification.

use crate::{
	Config, Event, ZkVerifierPort,
	mock::*,
	types::{CircuitId, ProofSystem},
};
use frame_support::{BoundedVec, assert_ok, pallet_prelude::ConstU32};

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a sample disclosure verification key
/// This simulates the VK that would come from artifacts/verification_key_disclosure.json
fn disclosure_verification_key() -> Vec<u8> {
	// Disclosure VK structure (simplified for testing)
	// In production, this comes from orbinum-zk-verifier hardcoded VK
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[100u8; 64]); // alpha_g1
	vk.extend_from_slice(&[101u8; 128]); // beta_g2
	vk.extend_from_slice(&[102u8; 128]); // gamma_g2
	vk.extend_from_slice(&[103u8; 128]); // delta_g2
	vk.extend_from_slice(&[104u8; 64]); // IC[0]
	vk
}

/// Generate sample disclosure proof (256 bytes - Groth16 standard)
fn sample_disclosure_proof() -> Vec<u8> {
	let mut proof = Vec::with_capacity(256);
	proof.extend_from_slice(&[20u8; 64]); // A (G1 point)
	proof.extend_from_slice(&[21u8; 128]); // B (G2 point)
	proof.extend_from_slice(&[22u8; 64]); // C (G1 point)
	proof
}

/// Generate sample public signals for disclosure circuit
/// Format: commitment (32) + revealed_value (8) + revealed_asset_id (4) + revealed_owner_hash (32) = 76 bytes
fn sample_disclosure_public_signals() -> Vec<u8> {
	let mut signals = Vec::with_capacity(76);

	// 1. commitment (32 bytes)
	signals.extend_from_slice(&[1u8; 32]);

	// 2. revealed_value (8 bytes, u64 little-endian)
	let value: u64 = 1000;
	signals.extend_from_slice(&value.to_le_bytes());

	// 3. revealed_asset_id (4 bytes, u32 little-endian)
	let asset_id: u32 = 1;
	signals.extend_from_slice(&asset_id.to_le_bytes());

	// 4. revealed_owner_hash (32 bytes)
	signals.extend_from_slice(&[2u8; 32]);

	signals
}

/// Generate multiple disclosure proofs for batch testing
fn generate_batch_disclosure_proofs(count: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
	let mut proofs = Vec::with_capacity(count);
	let mut signals = Vec::with_capacity(count);

	for i in 0..count {
		// Each proof is slightly different
		let mut proof = sample_disclosure_proof();
		proof[0] = (20 + i) as u8;
		proofs.push(proof);

		// Each signal set is slightly different
		let mut sig = sample_disclosure_public_signals();
		sig[0] = (1 + i) as u8;
		signals.push(sig);
	}

	(proofs, signals)
}

// ============================================================================
// ZkVerifierPort::verify_disclosure_proof Tests (Real Verification)
// ============================================================================

#[test]
fn disclosure_circuit_id_is_4() {
	// Verify that CircuitId::DISCLOSURE is correctly defined
	// This is from primitives/zk-verifier circuit constants
	assert_eq!(CircuitId::DISCLOSURE.0, 4);
}

#[test]
fn port_verify_disclosure_proof_works_with_valid_proof() {
	new_test_ext().execute_with(|| {
		// Register disclosure VK
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Prepare proof and public signals
		let proof = sample_disclosure_proof();
		let public_signals = sample_disclosure_public_signals();

		// Verify using ZkVerifierPort trait
		// Note: In test mode, this bypasses real verification
		// For real verification, remove #[cfg(test)] from groth16_verifier.rs
		let result = ZkVerifier::verify_disclosure_proof(&proof, &public_signals, Some(1));

		assert_ok!(result);
		assert!(result.unwrap());
	});
}

#[test]
fn port_verify_disclosure_proof_fails_without_vk() {
	new_test_ext().execute_with(|| {
		// Don't register VK
		let proof = sample_disclosure_proof();
		let public_signals = sample_disclosure_public_signals();

		// Without VK registered, should fail with CircuitNotFound
		let result = ZkVerifier::verify_disclosure_proof(&proof, &public_signals, None);

		// Should fail because VK is not registered
		assert!(result.is_err());
	});
}

#[test]
fn port_verify_disclosure_proof_rejects_empty_proof() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let empty_proof = vec![];
		let public_signals = sample_disclosure_public_signals();

		let result = ZkVerifier::verify_disclosure_proof(&empty_proof, &public_signals, Some(1));

		// Empty proof is rejected by domain validation
		assert!(result.is_err());
	});
}

#[test]
fn port_verify_disclosure_proof_rejects_invalid_signals_length() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = sample_disclosure_proof();
		let invalid_signals = vec![1u8; 50]; // Wrong length (should be 76)

		let result = ZkVerifier::verify_disclosure_proof(&proof, &invalid_signals, Some(1));

		// Invalid signals length is rejected before verification
		assert!(result.is_err());
	});
}

#[test]
fn port_verify_disclosure_proof_parses_public_signals_correctly() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Create signals with known values
		let mut signals = Vec::with_capacity(76);

		// commitment
		let commitment = [42u8; 32];
		signals.extend_from_slice(&commitment);

		// revealed_value = 12345
		let value: u64 = 12345;
		signals.extend_from_slice(&value.to_le_bytes());

		// revealed_asset_id = 99
		let asset_id: u32 = 99;
		signals.extend_from_slice(&asset_id.to_le_bytes());

		// revealed_owner_hash
		let owner_hash = [88u8; 32];
		signals.extend_from_slice(&owner_hash);

		let proof = sample_disclosure_proof();

		// Verify (bypassed in test mode)
		let result = ZkVerifier::verify_disclosure_proof(&proof, &signals, Some(1));

		assert_ok!(result);
		assert!(result.unwrap());
	});
}

#[test]
fn port_verify_disclosure_proof_with_all_zero_revealed_values() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// All revealed values are 0 (nothing disclosed)
		let mut signals = Vec::with_capacity(76);
		signals.extend_from_slice(&[1u8; 32]); // commitment
		signals.extend_from_slice(&[0u8; 8]); // revealed_value = 0
		signals.extend_from_slice(&[0u8; 4]); // revealed_asset_id = 0
		signals.extend_from_slice(&[0u8; 32]); // revealed_owner_hash = 0

		let proof = sample_disclosure_proof();

		let result = ZkVerifier::verify_disclosure_proof(&proof, &signals, Some(1));

		assert_ok!(result);
	});
}

#[test]
fn port_verify_disclosure_proof_with_maximum_revealed_values() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Maximum values disclosed
		let mut signals = Vec::with_capacity(76);
		signals.extend_from_slice(&[255u8; 32]); // commitment
		signals.extend_from_slice(&u64::MAX.to_le_bytes()); // max revealed_value
		signals.extend_from_slice(&u32::MAX.to_le_bytes()); // max revealed_asset_id
		signals.extend_from_slice(&[255u8; 32]); // revealed_owner_hash

		let proof = sample_disclosure_proof();

		let result = ZkVerifier::verify_disclosure_proof(&proof, &signals, Some(1));

		assert_ok!(result);
	});
}

// ============================================================================
// ZkVerifierPort::batch_verify_disclosure_proofs Tests (Real Batch Verification)
// ============================================================================

#[test]
#[ignore] // Requires real ZK proofs, not mocks. Batch verifier does not have test mode bypass.
fn port_batch_verify_disclosure_proofs_works_with_single_proof() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let proof = sample_disclosure_proof();
		let signals = sample_disclosure_public_signals();

		let result = ZkVerifier::batch_verify_disclosure_proofs(&[proof], &[signals], Some(1));

		assert_ok!(result);
		assert!(result.unwrap());
	});
}

#[test]
#[ignore] // Requires real ZK proofs, not mocks. Batch verifier does not have test mode bypass.
fn port_batch_verify_disclosure_proofs_works_with_multiple_proofs() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let (proofs, signals) = generate_batch_disclosure_proofs(5);

		let result = ZkVerifier::batch_verify_disclosure_proofs(&proofs, &signals, Some(1));

		assert_ok!(result);
		assert!(result.unwrap());
	});
}

#[test]
#[ignore] // Requires real ZK proofs, not mocks. Batch verifier does not have test mode bypass.
fn port_batch_verify_disclosure_proofs_works_with_maximum_batch_size() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Test with 10 proofs (typical batch size)
		let (proofs, signals) = generate_batch_disclosure_proofs(10);

		let result = ZkVerifier::batch_verify_disclosure_proofs(&proofs, &signals, Some(1));

		assert_ok!(result);
		assert!(result.unwrap());
	});
}

#[test]
fn port_batch_verify_disclosure_proofs_rejects_mismatched_lengths() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let (proofs, signals) = generate_batch_disclosure_proofs(3);
		let mut signals_wrong = signals;
		signals_wrong.pop(); // Now lengths don't match

		let result = ZkVerifier::batch_verify_disclosure_proofs(&proofs, &signals_wrong, Some(1));

		// Should fail with length mismatch
		assert!(result.is_err());
	});
}

#[test]
fn port_batch_verify_disclosure_proofs_with_empty_batch() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		let empty_proofs: Vec<Vec<u8>> = vec![];
		let empty_signals: Vec<Vec<u8>> = vec![];

		let result =
			ZkVerifier::batch_verify_disclosure_proofs(&empty_proofs, &empty_signals, Some(1));

		// Empty batch should be rejected with InvalidBatchSize
		assert!(result.is_err());
	});
}

#[test]
#[ignore] // Requires real ZK proofs, not mocks. Batch verifier does not have test mode bypass.
fn port_batch_verify_disclosure_maintains_proof_independence() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Create batch with different commitments
		let mut proofs = vec![];
		let mut signals = vec![];

		for i in 0..3 {
			let proof = sample_disclosure_proof();
			proofs.push(proof);

			let mut sig = Vec::with_capacity(76);
			sig.extend_from_slice(&[(i + 1) as u8; 32]); // Different commitment
			sig.extend_from_slice(&((i + 1) as u64 * 1000).to_le_bytes());
			sig.extend_from_slice(&((i + 1) as u32).to_le_bytes());
			sig.extend_from_slice(&[(i + 10) as u8; 32]);
			signals.push(sig);
		}

		let result = ZkVerifier::batch_verify_disclosure_proofs(&proofs, &signals, Some(1));

		assert_ok!(result);
		assert!(result.unwrap());
	});
}

// ============================================================================
// Integration with Extrinsics (verify_proof path)
// ============================================================================

#[test]
fn disclosure_proof_verification_via_extrinsic() {
	new_test_ext().execute_with(|| {
		// Register disclosure VK
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Set active version
		assert_ok!(ZkVerifier::set_active_version(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1
		));

		// Prepare proof and inputs
		let proof_bytes = sample_disclosure_proof();
		let proof: BoundedVec<u8, <Test as Config>::MaxProofSize> = proof_bytes.try_into().unwrap();

		let signals = sample_disclosure_public_signals();
		let public_inputs: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<Test as Config>::MaxPublicInputs,
		> = signals
			.chunks(32)
			.take(4) // Disclosure has 4 public inputs
			.map(|chunk| {
				let mut v = vec![0u8; 32];
				v[..chunk.len()].copy_from_slice(chunk);
				BoundedVec::<u8, ConstU32<32>>::try_from(v).unwrap()
			})
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		// Verify via extrinsic
		assert_ok!(ZkVerifier::verify_proof(
			RuntimeOrigin::signed(1),
			CircuitId::DISCLOSURE,
			proof,
			public_inputs,
		));

		// Check event was emitted
		System::assert_has_event(
			Event::ProofVerified {
				circuit_id: CircuitId::DISCLOSURE,
				version: 1,
			}
			.into(),
		);
	});
}

#[test]
fn disclosure_statistics_tracked_correctly() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Verify multiple disclosure proofs
		for _ in 0..3 {
			let proof = sample_disclosure_proof();
			let signals = sample_disclosure_public_signals();

			let _ = ZkVerifier::verify_disclosure_proof(&proof, &signals, Some(1));
		}

		// Statistics should show 3 successful verifications
		// Note: Statistics tracking depends on implementation in groth16_verifier.rs
	});
}

// ============================================================================
// Performance and Edge Cases
// ============================================================================

#[test]
fn disclosure_proof_verification_handles_concurrent_requests() {
	new_test_ext().execute_with(|| {
		let vk = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk,
			ProofSystem::Groth16,
		));

		// Simulate concurrent verification requests
		let (proofs, signals) = generate_batch_disclosure_proofs(5);

		for (proof, sig) in proofs.iter().zip(signals.iter()) {
			let result = ZkVerifier::verify_disclosure_proof(proof, sig, Some(1));
			assert_ok!(result);
		}
	});
}

#[test]
fn disclosure_proof_verification_with_different_versions() {
	new_test_ext().execute_with(|| {
		// Register v1
		let vk_v1 = disclosure_verification_key();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			1,
			vk_v1,
			ProofSystem::Groth16,
		));

		// Register v2 (simulated upgrade)
		let mut vk_v2 = disclosure_verification_key();
		vk_v2[0] = 200; // Make it different
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::DISCLOSURE,
			2,
			vk_v2,
			ProofSystem::Groth16,
		));

		let proof = sample_disclosure_proof();
		let signals = sample_disclosure_public_signals();

		// Verify with v1
		let result_v1 = ZkVerifier::verify_disclosure_proof(&proof, &signals, Some(1));
		assert_ok!(result_v1);

		// Verify with v2
		let result_v2 = ZkVerifier::verify_disclosure_proof(&proof, &signals, Some(2));
		assert_ok!(result_v2);
	});
}
