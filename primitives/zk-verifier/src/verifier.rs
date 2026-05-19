//! Groth16 proof verifier — stateless, all methods are static.

use alloc::vec::Vec;

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

	/// Estimate the weight cost for verifying a proof with `num_public_inputs` inputs.
	pub fn estimate_verification_cost(num_public_inputs: usize) -> u64 {
		BASE_VERIFICATION_COST + (num_public_inputs as u64 * PER_INPUT_COST)
	}

	/// Batch-verify multiple proofs against the same circuit VK.
	///
	/// Significantly more efficient than individual calls due to pairing batching.
	/// Returns `Ok(true)` if all proofs are valid, `Ok(false)` if any fail,
	/// `Err` if inputs are malformed.
	pub fn batch_verify(
		vk: &VerifyingKey,
		public_inputs: &[PublicInputs],
		proofs: &[Proof],
	) -> Result<bool, VerifierError> {
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

		let pvk = vk.prepare()?;

		let mut ark_proofs = Vec::with_capacity(proofs.len());
		for proof in proofs {
			ark_proofs.push(proof.to_ark_proof()?);
		}

		let mut all_inputs = Vec::with_capacity(public_inputs.len());
		for inputs in public_inputs {
			all_inputs.push(inputs.to_field_elements()?);
		}

		let mut total_r = <Bn254 as Pairing>::ScalarField::zero();
		let mut combined_inputs = <Bn254 as Pairing>::G1::zero();
		let mut combined_c = <Bn254 as Pairing>::G1::zero();

		let mut g1_prepared = Vec::with_capacity(proofs.len() + 2);
		let mut g2_prepared = Vec::with_capacity(proofs.len() + 2);

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

			let r_a = proof.a.mul_bigint(r_bigint);
			g1_prepared.push(<Bn254 as Pairing>::G1Prepared::from(r_a.into_affine()));
			g2_prepared.push(<Bn254 as Pairing>::G2Prepared::from(proof.b));

			let prepared_inputs = Groth16::<Bn254>::prepare_inputs(&pvk, inputs)
				.map_err(|_| VerifierError::VerificationFailed)?;
			combined_inputs += prepared_inputs.mul_bigint(r_bigint);
			combined_c += proof.c.mul_bigint(r_bigint);
		}

		g1_prepared.push(<Bn254 as Pairing>::G1Prepared::from(
			combined_inputs.into_affine(),
		));
		g2_prepared.push(pvk.gamma_g2_neg_pc.clone());

		g1_prepared.push(<Bn254 as Pairing>::G1Prepared::from(
			combined_c.into_affine(),
		));
		g2_prepared.push(pvk.delta_g2_neg_pc.clone());

		let qap = <Bn254 as Pairing>::multi_miller_loop(g1_prepared, g2_prepared);
		let test = <Bn254 as Pairing>::final_exponentiation(qap)
			.ok_or(VerifierError::VerificationFailed)?;

		let target = pvk.alpha_g1_beta_g2.pow(total_r.into_bigint());
		Ok(test.0 == target)
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

	// ─── batch_verify ────────────────────────────────────────────────────

	#[test]
	fn test_batch_verify_empty_arrays() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		assert!(Groth16Verifier::batch_verify(&vk_wrapper, &[], &[]).unwrap());
	}

	#[test]
	fn test_batch_verify_mismatched_lengths() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let result = Groth16Verifier::batch_verify(
			&vk_wrapper,
			&alloc::vec![create_mock_inputs(5)],
			&alloc::vec![create_mock_proof(), create_mock_proof()],
		);
		assert!(matches!(result, Err(VerifierError::VerificationFailed)));
	}

	#[test]
	fn test_batch_verify_single_proof() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let result = Groth16Verifier::batch_verify(
			&vk_wrapper,
			&alloc::vec![create_mock_inputs(5)],
			&alloc::vec![create_mock_proof()],
		);
		assert!(result.is_ok());
		assert!(!result.unwrap());
	}

	#[test]
	fn test_batch_verify_multiple_proofs() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let result = Groth16Verifier::batch_verify(
			&vk_wrapper,
			&alloc::vec![
				create_mock_inputs(5),
				create_mock_inputs(5),
				create_mock_inputs(5)
			],
			&alloc::vec![
				create_mock_proof(),
				create_mock_proof(),
				create_mock_proof()
			],
		);
		assert!(result.is_ok());
		assert!(!result.unwrap());
	}

	#[test]
	fn test_batch_verify_with_invalid_proof() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let result = Groth16Verifier::batch_verify(
			&vk_wrapper,
			&alloc::vec![create_mock_inputs(5), create_mock_inputs(5)],
			&alloc::vec![create_mock_proof(), Proof::new(alloc::vec![0u8; 3])],
		);
		assert!(result.is_err());
	}

	#[test]
	fn test_batch_verify_input_count_mismatch() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let result = Groth16Verifier::batch_verify(
			&vk_wrapper,
			&alloc::vec![create_mock_inputs(3), create_mock_inputs(3)],
			&alloc::vec![create_mock_proof(), create_mock_proof()],
		);
		assert!(result.is_err());
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

	#[test]
	fn test_verify_and_batch_verify_consistency() {
		let vk_wrapper = VerifyingKey::from_ark_vk(&create_mock_ark_vk(5)).unwrap();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let single_result = Groth16Verifier::verify(&vk_wrapper, &inputs, &proof);
		let batch_result =
			Groth16Verifier::batch_verify(&vk_wrapper, &alloc::vec![inputs], &alloc::vec![proof]);

		assert!(single_result.is_err());
		assert!(batch_result.is_ok());
		assert!(!batch_result.unwrap());
	}
}
