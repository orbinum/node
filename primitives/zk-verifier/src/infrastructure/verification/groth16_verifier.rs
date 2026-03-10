//! Groth16 verifier implementation
//!
//! This module provides the core verification logic for Groth16 proofs
//! using the BN254 elliptic curve.

use crate::{
	domain::ports::VerifierPort,
	domain::value_objects::{
		circuit_constants::{BASE_VERIFICATION_COST, PER_INPUT_COST},
		errors::VerifierError,
		proof_types::{Proof, PublicInputs, VerifyingKey},
	},
	Bn254,
};
use ark_groth16::{Groth16, PreparedVerifyingKey};

/// Groth16 proof verifier
pub struct Groth16Verifier;

impl Groth16Verifier {
	/// Creates a stateless verifier instance.
	pub fn new() -> Self {
		Self
	}

	/// Verify a Groth16 proof
	///
	/// # Arguments
	///
	/// * `vk` - The verifying key
	/// * `public_inputs` - The public inputs to the proof
	/// * `proof` - The proof to verify
	///
	/// # Returns
	///
	/// `Ok(())` if the proof is valid, `Err(VerifierError)` otherwise
	///
	/// # Example
	///
	/// ```rust,ignore
	/// let result = Groth16Verifier::verify(&vk, &inputs, &proof);
	/// assert!(result.is_ok());
	/// ```
	pub fn verify(
		vk: &VerifyingKey,
		public_inputs: &PublicInputs,
		proof: &Proof,
	) -> Result<(), VerifierError> {
		// Deserialize the verifying key
		let ark_vk = vk.to_ark_vk()?;
		let pvk = PreparedVerifyingKey::from(ark_vk);

		// Deserialize the proof
		let ark_proof = proof.to_ark_proof()?;

		// Convert public inputs to field elements
		let inputs = public_inputs.to_field_elements()?;

		// Verify the proof
		let valid = Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &inputs)
			.map_err(|_| VerifierError::VerificationFailed)?;

		if valid {
			Ok(())
		} else {
			Err(VerifierError::VerificationFailed)
		}
	}

	/// Verify a proof with a pre-prepared verifying key
	///
	/// This is more efficient if you're verifying multiple proofs with
	/// the same verifying key.
	pub fn verify_with_prepared_vk(
		pvk: &PreparedVerifyingKey<Bn254>,
		public_inputs: &PublicInputs,
		proof: &Proof,
	) -> Result<(), VerifierError> {
		// Deserialize the proof
		let ark_proof = proof.to_ark_proof()?;

		// Convert public inputs to field elements
		let inputs = public_inputs.to_field_elements()?;

		// Verify the proof
		let valid = Groth16::<Bn254>::verify_proof(pvk, &ark_proof, &inputs)
			.map_err(|_| VerifierError::VerificationFailed)?;

		if valid {
			Ok(())
		} else {
			Err(VerifierError::VerificationFailed)
		}
	}

	/// Estimate the gas cost for verifying a proof
	///
	/// This is useful for setting appropriate transaction weights
	pub fn estimate_verification_cost(num_public_inputs: usize) -> u64 {
		// Use constants from core
		BASE_VERIFICATION_COST + (num_public_inputs as u64 * PER_INPUT_COST)
	}

	/// Verify multiple Groth16 proofs in a single batch operation
	///
	/// This is significantly more efficient than verifying proofs individually
	/// due to pairing batching and other cryptographic optimizations.
	pub fn batch_verify(
		vk: &VerifyingKey,
		public_inputs: &[PublicInputs],
		proofs: &[Proof],
	) -> Result<bool, VerifierError> {
		// arkworks 0.5.0: mul_bigint is in PrimeGroup trait
		use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
		use ark_ff::{Field, PrimeField};
		use ark_std::Zero;
		use sha2::{Digest, Sha256};

		if public_inputs.len() != proofs.len() {
			return Err(VerifierError::VerificationFailed);
		}

		if proofs.is_empty() {
			return Ok(true);
		}

		// 1. Deserialize everything
		let pvk = vk.prepare()?;

		let mut ark_proofs = alloc::vec::Vec::with_capacity(proofs.len());
		for proof in proofs {
			ark_proofs.push(proof.to_ark_proof()?);
		}

		let mut all_inputs = alloc::vec::Vec::with_capacity(public_inputs.len());
		for inputs in public_inputs {
			all_inputs.push(inputs.to_field_elements()?);
		}

		// 2. Setup accumulators

		let mut total_r = <Bn254 as Pairing>::ScalarField::zero();
		let mut combined_inputs = <Bn254 as Pairing>::G1::zero();
		let mut combined_c = <Bn254 as Pairing>::G1::zero();

		let mut g1_prepared = alloc::vec::Vec::with_capacity(proofs.len() + 2);
		let mut g2_prepared = alloc::vec::Vec::with_capacity(proofs.len() + 2);

		// 3. Combine proofs into linear combination
		for (index, (inputs, proof)) in all_inputs.iter().zip(ark_proofs.iter()).enumerate() {
			let mut hasher = Sha256::new();
			hasher.update(b"orbinum-zk-verifier-batch-v1");
			hasher.update(vk.as_bytes());
			hasher.update((index as u64).to_le_bytes());
			hasher.update(proofs[index].as_bytes());
			for input in &public_inputs[index].inputs {
				hasher.update(input);
			}
			let digest = hasher.finalize();
			let mut r = <Bn254 as Pairing>::ScalarField::from_le_bytes_mod_order(&digest);
			if r.is_zero() {
				r = <Bn254 as Pairing>::ScalarField::from(1u64);
			}
			let r_bigint = r.into_bigint();
			total_r += r;

			// Add (r * A, B) to the pairing list
			let r_a = proof.a.mul_bigint(r_bigint);
			g1_prepared.push(<Bn254 as Pairing>::G1Prepared::from(r_a.into_affine()));
			g2_prepared.push(<Bn254 as Pairing>::G2Prepared::from(proof.b));

			// Accumulate r * (Σ x_i γ_i)
			let prepared_inputs = Groth16::<Bn254>::prepare_inputs(&pvk, inputs)
				.map_err(|_| VerifierError::VerificationFailed)?;
			combined_inputs += prepared_inputs.mul_bigint(r_bigint);

			// Accumulate r * C
			combined_c += proof.c.mul_bigint(r_bigint);
		}

		// 4. Add the combined terms for -gamma and -delta
		// Equations: e(Σ r_j A_j, B_j) * e(combined_inputs, -gamma) * e(combined_c, -delta) = e(alpha, beta)^Σ r_j
		g1_prepared.push(<Bn254 as Pairing>::G1Prepared::from(
			combined_inputs.into_affine(),
		));
		g2_prepared.push(pvk.gamma_g2_neg_pc.clone());

		g1_prepared.push(<Bn254 as Pairing>::G1Prepared::from(
			combined_c.into_affine(),
		));
		g2_prepared.push(pvk.delta_g2_neg_pc.clone());

		// 5. Compute consolidated pairing
		let qap = <Bn254 as Pairing>::multi_miller_loop(g1_prepared, g2_prepared);
		let test = <Bn254 as Pairing>::final_exponentiation(qap)
			.ok_or(VerifierError::VerificationFailed)?;

		// 6. Compare with target: e(alpha, beta)^Σ r_j
		let target = pvk.alpha_g1_beta_g2.pow(total_r.into_bigint());

		Ok(test.0 == target)
	}
}

impl Default for Groth16Verifier {
	fn default() -> Self {
		Self::new()
	}
}

impl VerifierPort for Groth16Verifier {
	type PreparedKey = PreparedVerifyingKey<Bn254>;

	fn verify(
		&self,
		vk: &VerifyingKey,
		public_inputs: &PublicInputs,
		proof: &Proof,
	) -> Result<(), VerifierError> {
		Self::verify(vk, public_inputs, proof)
	}

	fn verify_prepared(
		&self,
		prepared_vk: &Self::PreparedKey,
		public_inputs: &PublicInputs,
		proof: &Proof,
	) -> Result<(), VerifierError> {
		Self::verify_with_prepared_vk(prepared_vk, public_inputs, proof)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::domain::value_objects::circuit_constants::{BASE_VERIFICATION_COST, PER_INPUT_COST};
	use ark_bn254::{Bn254, Fr as Bn254Fr, G1Affine, G2Affine};
	use ark_ec::AffineRepr;
	use ark_ff::{BigInteger, PrimeField};
	use ark_groth16::VerifyingKey as ArkVerifyingKey;
	use ark_serialize::CanonicalSerialize;

	// Helper: Create mock proof with valid curve points
	fn create_mock_proof() -> Proof {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;

		// Use generator points (always valid on curve)
		let a = G1Affine::generator();
		let b = G2Affine::generator();
		let c = G1Affine::generator();

		let mut proof_bytes = alloc::vec::Vec::new();
		a.serialize_compressed(&mut proof_bytes).unwrap();
		b.serialize_compressed(&mut proof_bytes).unwrap();
		c.serialize_compressed(&mut proof_bytes).unwrap();

		Proof::new(proof_bytes)
	}

	// Helper: Create mock public inputs
	fn create_mock_inputs(count: usize) -> PublicInputs {
		let mut inputs = alloc::vec::Vec::new();
		for i in 0..count {
			let field = Bn254Fr::from(i as u64 + 1);
			// Convert field to bytes (big-endian, 32 bytes)
			let bigint = field.into_bigint();
			let bytes_vec = bigint.to_bytes_be();
			let mut bytes = [0u8; 32];
			let start = 32 - bytes_vec.len();
			bytes[start..].copy_from_slice(&bytes_vec);
			inputs.push(bytes);
		}
		PublicInputs::new(inputs)
	}

	fn create_mock_ark_vk(expected_inputs: usize) -> ArkVerifyingKey<Bn254> {
		ArkVerifyingKey {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: G2Affine::generator(),
			gamma_abc_g1: (0..=expected_inputs)
				.map(|_| G1Affine::generator())
				.collect(),
		}
	}

	// estimate_verification_cost tests
	#[test]
	fn test_estimate_verification_cost_zero_inputs() {
		let cost = Groth16Verifier::estimate_verification_cost(0);
		assert_eq!(cost, BASE_VERIFICATION_COST);
	}

	#[test]
	fn test_estimate_verification_cost_one_input() {
		let cost = Groth16Verifier::estimate_verification_cost(1);
		assert_eq!(cost, BASE_VERIFICATION_COST + PER_INPUT_COST);
	}

	#[test]
	fn test_estimate_verification_cost_five_inputs() {
		let cost = Groth16Verifier::estimate_verification_cost(5);
		assert_eq!(cost, BASE_VERIFICATION_COST + (5 * PER_INPUT_COST));
	}

	#[test]
	fn test_estimate_verification_cost_ten_inputs() {
		let cost = Groth16Verifier::estimate_verification_cost(10);
		assert_eq!(cost, BASE_VERIFICATION_COST + (10 * PER_INPUT_COST));
	}

	#[test]
	fn test_estimate_verification_cost_increases_linearly() {
		let cost_5 = Groth16Verifier::estimate_verification_cost(5);
		let cost_10 = Groth16Verifier::estimate_verification_cost(10);
		assert_eq!(cost_10 - cost_5, 5 * PER_INPUT_COST);
	}

	// verify tests (basic structure)
	#[test]
	fn test_verify_detects_invalid_proof_structure() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();
		let inputs = create_mock_inputs(5);

		// Create an invalid proof with wrong byte length
		let invalid_proof = Proof::new(alloc::vec![0u8; 10]);

		let result = Groth16Verifier::verify(&vk_wrapper, &inputs, &invalid_proof);
		assert!(result.is_err());
	}

	#[test]
	fn test_verify_detects_input_count_mismatch() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		// Transfer circuit expects 5 inputs, provide 3
		let inputs = create_mock_inputs(3);
		let proof = create_mock_proof();

		let result = Groth16Verifier::verify(&vk_wrapper, &inputs, &proof);
		// Should fail - either during verification or input preparation
		assert!(result.is_err());
	}

	#[test]
	fn test_verify_accepts_correct_input_count() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		// Transfer circuit expects 5 inputs
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = Groth16Verifier::verify(&vk_wrapper, &inputs, &proof);
		// Will fail verification but not due to structure issues
		// Mock proof won't pass cryptographic verification
		assert!(result.is_err());
		match result {
			Err(VerifierError::VerificationFailed) => {
				// Expected - mock proof doesn't satisfy proof equation
			}
			_ => panic!("Expected VerificationFailed error"),
		}
	}

	#[test]
	fn test_verify_with_unshield_vk() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		// Unshield circuit expects 5 inputs
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = Groth16Verifier::verify(&vk_wrapper, &inputs, &proof);
		assert!(result.is_err());
		match result {
			Err(VerifierError::VerificationFailed) => {
				// Expected - mock proof won't verify
			}
			_ => panic!("Expected VerificationFailed error"),
		}
	}

	#[test]
	fn test_verify_with_disclosure_vk() {
		let vk = create_mock_ark_vk(4);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		// Disclosure circuit expects 4 inputs
		let inputs = create_mock_inputs(4);
		let proof = create_mock_proof();

		let result = Groth16Verifier::verify(&vk_wrapper, &inputs, &proof);
		assert!(result.is_err());
		match result {
			Err(VerifierError::VerificationFailed) => {
				// Expected
			}
			_ => panic!("Expected VerificationFailed error"),
		}
	}

	// verify_with_prepared_vk tests
	#[test]
	fn test_verify_with_prepared_vk_structure() {
		let vk = create_mock_ark_vk(5);
		let pvk = PreparedVerifyingKey::from(vk);

		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = Groth16Verifier::verify_with_prepared_vk(&pvk, &inputs, &proof);
		assert!(result.is_err());
		match result {
			Err(VerifierError::VerificationFailed) => {
				// Expected
			}
			_ => panic!("Expected VerificationFailed error"),
		}
	}

	#[test]
	fn test_verify_with_prepared_vk_input_mismatch() {
		let vk = create_mock_ark_vk(5);
		let pvk = PreparedVerifyingKey::from(vk);

		// Wrong input count
		let inputs = create_mock_inputs(3);
		let proof = create_mock_proof();

		let result = Groth16Verifier::verify_with_prepared_vk(&pvk, &inputs, &proof);
		assert!(result.is_err());
	}

	#[test]
	fn test_verify_with_prepared_vk_invalid_proof() {
		let vk = create_mock_ark_vk(5);
		let pvk = PreparedVerifyingKey::from(vk);

		let inputs = create_mock_inputs(5);
		let invalid_proof = Proof::new(alloc::vec![0u8; 5]);

		let result = Groth16Verifier::verify_with_prepared_vk(&pvk, &inputs, &invalid_proof);
		assert!(result.is_err());
	}

	// batch_verify tests
	#[test]
	fn test_batch_verify_empty_arrays() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		let result = Groth16Verifier::batch_verify(&vk_wrapper, &[], &[]);
		assert!(result.is_ok());
		assert!(result.unwrap());
	}

	#[test]
	fn test_batch_verify_mismatched_lengths() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		let inputs = alloc::vec![create_mock_inputs(5)];
		let proofs = alloc::vec![create_mock_proof(), create_mock_proof()];

		let result = Groth16Verifier::batch_verify(&vk_wrapper, &inputs, &proofs);
		assert!(result.is_err());
		match result {
			Err(VerifierError::VerificationFailed) => {
				// Expected
			}
			_ => panic!("Expected VerificationFailed error"),
		}
	}

	#[test]
	fn test_batch_verify_single_proof() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		let inputs = alloc::vec![create_mock_inputs(5)];
		let proofs = alloc::vec![create_mock_proof()];

		let result = Groth16Verifier::batch_verify(&vk_wrapper, &inputs, &proofs);
		// Will fail verification but not structure validation
		assert!(result.is_ok());
		assert!(!result.unwrap());
	}

	#[test]
	fn test_batch_verify_multiple_proofs() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		let inputs = alloc::vec![
			create_mock_inputs(5),
			create_mock_inputs(5),
			create_mock_inputs(5),
		];
		let proofs = alloc::vec![
			create_mock_proof(),
			create_mock_proof(),
			create_mock_proof(),
		];

		let result = Groth16Verifier::batch_verify(&vk_wrapper, &inputs, &proofs);
		assert!(result.is_ok());
		// Mock proofs won't verify cryptographically
		assert!(!result.unwrap());
	}

	#[test]
	fn test_batch_verify_with_invalid_proof() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		let inputs = alloc::vec![create_mock_inputs(5), create_mock_inputs(5)];
		let proofs = alloc::vec![create_mock_proof(), Proof::new(alloc::vec![0u8; 3])];

		let result = Groth16Verifier::batch_verify(&vk_wrapper, &inputs, &proofs);
		assert!(result.is_err());
	}

	#[test]
	fn test_batch_verify_input_count_mismatch() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		// Transfer expects 5 inputs, providing 3
		let inputs = alloc::vec![create_mock_inputs(3), create_mock_inputs(3)];
		let proofs = alloc::vec![create_mock_proof(), create_mock_proof()];

		let result = Groth16Verifier::batch_verify(&vk_wrapper, &inputs, &proofs);
		assert!(result.is_err());
	}

	// Integration-style tests
	#[test]
	fn test_all_circuits_can_prepare_vk() {
		// Transfer
		let transfer_vk = create_mock_ark_vk(5);
		let transfer_wrapper = VerifyingKey::from_ark_vk(&transfer_vk).unwrap();
		assert!(transfer_wrapper.prepare().is_ok());

		// Unshield
		let unshield_vk = create_mock_ark_vk(5);
		let unshield_wrapper = VerifyingKey::from_ark_vk(&unshield_vk).unwrap();
		assert!(unshield_wrapper.prepare().is_ok());

		// Disclosure
		let disclosure_vk = create_mock_ark_vk(4);
		let disclosure_wrapper = VerifyingKey::from_ark_vk(&disclosure_vk).unwrap();
		assert!(disclosure_wrapper.prepare().is_ok());
	}

	#[test]
	fn test_verify_and_batch_verify_consistency() {
		let vk = create_mock_ark_vk(5);
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		// Single verify
		let single_result = Groth16Verifier::verify(&vk_wrapper, &inputs, &proof);

		// Batch verify with single proof
		let batch_result = Groth16Verifier::batch_verify(
			&vk_wrapper,
			&alloc::vec![inputs.clone()],
			&alloc::vec![proof.clone()],
		);

		// Both should fail with mock proof
		assert!(single_result.is_err());
		assert!(batch_result.is_ok());
		assert!(!batch_result.unwrap());
	}
}
