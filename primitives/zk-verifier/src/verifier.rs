//! Groth16 proof verifier — stateless, all methods are static.

use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey};

use crate::{
	Proof, PublicInputs, VerifierError, VerifyingKey, BASE_VERIFICATION_COST, PER_INPUT_COST,
};

/// Stateless Groth16 verifier over BN254.
pub struct Groth16Verifier;

impl Groth16Verifier {
	/// Verify a Groth16 proof. Deserializes and prepares the VK on every call.
	/// Use [`verify_with_prepared_vk`] when verifying multiple proofs for the same circuit.
	pub fn verify(
		vk: &VerifyingKey,
		public_inputs: &PublicInputs,
		proof: &Proof,
	) -> Result<(), VerifierError> {
		let pvk = PreparedVerifyingKey::from(vk.to_ark_vk()?);
		let ark_proof = proof.to_ark_proof()?;
		let inputs = public_inputs.to_field_elements()?;
		let valid = Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &inputs)
			.map_err(|_| VerifierError::VerificationFailed)?;
		if valid {
			Ok(())
		} else {
			Err(VerifierError::VerificationFailed)
		}
	}

	/// Verify using a pre-prepared VK — more efficient when verifying multiple
	/// proofs against the same circuit (avoids repeated pairing setup).
	pub fn verify_with_prepared_vk(
		pvk: &PreparedVerifyingKey<Bn254>,
		public_inputs: &PublicInputs,
		proof: &Proof,
	) -> Result<(), VerifierError> {
		let ark_proof = proof.to_ark_proof()?;
		let inputs = public_inputs.to_field_elements()?;
		let valid = Groth16::<Bn254>::verify_proof(pvk, &ark_proof, &inputs)
			.map_err(|_| VerifierError::VerificationFailed)?;
		if valid {
			Ok(())
		} else {
			Err(VerifierError::VerificationFailed)
		}
	}

	/// Rough cost of verifying a proof with `num_public_inputs` inputs.
	///
	/// Indicative only — on-chain weights come from benchmarks, not from here.
	/// Saturating rather than plain arithmetic because the release profile does
	/// not enable `overflow-checks`, so an absurd input would silently wrap and
	/// return a cost far below the real one.
	pub fn estimate_verification_cost(num_public_inputs: usize) -> u64 {
		BASE_VERIFICATION_COST
			.saturating_add((num_public_inputs as u64).saturating_mul(PER_INPUT_COST))
	}
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{BASE_VERIFICATION_COST, PER_INPUT_COST};
	use ark_bn254::{Bn254, Fr as Bn254Fr, G1Affine, G2Affine};
	use ark_ec::AffineRepr;
	use ark_ff::{BigInteger, PrimeField};
	use ark_groth16::VerifyingKey as ArkVerifyingKey;
	use ark_serialize::CanonicalSerialize;

	fn create_mock_proof() -> Proof {
		let a = G1Affine::generator();
		let b = G2Affine::generator();
		let c = G1Affine::generator();
		let mut proof_bytes = alloc::vec::Vec::new();
		a.serialize_compressed(&mut proof_bytes).unwrap();
		b.serialize_compressed(&mut proof_bytes).unwrap();
		c.serialize_compressed(&mut proof_bytes).unwrap();
		Proof::new(proof_bytes)
	}

	fn create_mock_inputs(count: usize) -> PublicInputs {
		let mut inputs = alloc::vec::Vec::new();
		for i in 0..count {
			let field = Bn254Fr::from(i as u64 + 1);
			let bytes_vec = field.into_bigint().to_bytes_be();
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

	// ─── estimate_verification_cost ─────────────────────────────────────

	#[test]
	fn test_estimate_verification_cost_zero_inputs() {
		assert_eq!(
			Groth16Verifier::estimate_verification_cost(0),
			BASE_VERIFICATION_COST
		);
	}

	#[test]
	fn test_estimate_verification_cost_one_input() {
		assert_eq!(
			Groth16Verifier::estimate_verification_cost(1),
			BASE_VERIFICATION_COST + PER_INPUT_COST
		);
	}

	#[test]
	fn test_estimate_verification_cost_five_inputs() {
		assert_eq!(
			Groth16Verifier::estimate_verification_cost(5),
			BASE_VERIFICATION_COST + (5 * PER_INPUT_COST)
		);
	}

	#[test]
	fn test_estimate_verification_cost_ten_inputs() {
		assert_eq!(
			Groth16Verifier::estimate_verification_cost(10),
			BASE_VERIFICATION_COST + (10 * PER_INPUT_COST)
		);
	}

	#[test]
	fn test_estimate_verification_cost_increases_linearly() {
		let cost_5 = Groth16Verifier::estimate_verification_cost(5);
		let cost_10 = Groth16Verifier::estimate_verification_cost(10);
		assert_eq!(cost_10 - cost_5, 5 * PER_INPUT_COST);
	}

	// ─── verify ──────────────────────────────────────────────────────────

	#[test]
	fn test_verify_detects_invalid_proof_structure() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let invalid_proof = Proof::new(alloc::vec![0u8; 10]);
		assert!(
			Groth16Verifier::verify(&vk_wrapper, &create_mock_inputs(5), &invalid_proof).is_err()
		);
	}

	#[test]
	fn test_verify_detects_input_count_mismatch() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		assert!(
			Groth16Verifier::verify(&vk_wrapper, &create_mock_inputs(3), &create_mock_proof())
				.is_err()
		);
	}

	#[test]
	fn test_verify_accepts_correct_input_count() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let result =
			Groth16Verifier::verify(&vk_wrapper, &create_mock_inputs(5), &create_mock_proof());
		assert!(matches!(result, Err(VerifierError::VerificationFailed)));
	}

	#[test]
	fn test_verify_with_unshield_vk() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let result =
			Groth16Verifier::verify(&vk_wrapper, &create_mock_inputs(5), &create_mock_proof());
		assert!(matches!(result, Err(VerifierError::VerificationFailed)));
	}

	#[test]
	fn test_verify_with_value_proof_vk() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(4)).unwrap();
		let result =
			Groth16Verifier::verify(&vk_wrapper, &create_mock_inputs(4), &create_mock_proof());
		assert!(matches!(result, Err(VerifierError::VerificationFailed)));
	}

	// ─── verify_with_prepared_vk ─────────────────────────────────────────

	#[test]
	fn test_verify_with_prepared_vk_structure() {
		let pvk = PreparedVerifyingKey::from(create_mock_ark_vk(5));
		let result = Groth16Verifier::verify_with_prepared_vk(
			&pvk,
			&create_mock_inputs(5),
			&create_mock_proof(),
		);
		assert!(matches!(result, Err(VerifierError::VerificationFailed)));
	}

	#[test]
	fn test_verify_with_prepared_vk_input_mismatch() {
		let pvk = PreparedVerifyingKey::from(create_mock_ark_vk(5));
		assert!(Groth16Verifier::verify_with_prepared_vk(
			&pvk,
			&create_mock_inputs(3),
			&create_mock_proof()
		)
		.is_err());
	}

	#[test]
	fn test_verify_with_prepared_vk_invalid_proof() {
		let pvk = PreparedVerifyingKey::from(create_mock_ark_vk(5));
		assert!(Groth16Verifier::verify_with_prepared_vk(
			&pvk,
			&create_mock_inputs(5),
			&Proof::new(alloc::vec![0u8; 5])
		)
		.is_err());
	}

	// ─── num_public_inputs ───────────────────────────────────────────────

	#[test]
	fn num_public_inputs_matches_vk_arity() {
		for count in [0usize, 1, 2, 4, 5, 7] {
			let vk = VerifyingKey::from_ark_vk(&create_mock_ark_vk(count)).unwrap();
			assert_eq!(vk.num_public_inputs().unwrap(), count);
		}
	}

	#[test]
	fn num_public_inputs_errors_on_malformed_vk() {
		let vk = VerifyingKey::new(alloc::vec![0u8; 10]);
		assert!(matches!(
			vk.num_public_inputs(),
			Err(VerifierError::InvalidVerifyingKey)
		));
	}

	// ─── integration ─────────────────────────────────────────────────────

	#[test]
	fn test_all_circuits_can_prepare_vk() {
		for count in [5usize, 5, 4, 2] {
			let vk = create_mock_ark_vk(count);
			let wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();
			assert!(wrapper.prepare().is_ok());
		}
	}
}
