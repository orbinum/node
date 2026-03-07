//! Groth16 verifier implementation
//!
//! This module provides the core verification logic for Groth16 proofs
//! using the BN254 elliptic curve.

use crate::{
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
		use ark_std::{rand::SeedableRng, UniformRand, Zero};

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

		// 2. Setup RNG and accumulators
		// Use a deterministic seed for protocol consistency.
		let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0);

		let mut total_r = <Bn254 as Pairing>::ScalarField::zero();
		let mut combined_inputs = <Bn254 as Pairing>::G1::zero();
		let mut combined_c = <Bn254 as Pairing>::G1::zero();

		let mut g1_prepared = alloc::vec::Vec::with_capacity(proofs.len() + 2);
		let mut g2_prepared = alloc::vec::Vec::with_capacity(proofs.len() + 2);

		// 3. Combine proofs into linear combination
		for (inputs, proof) in all_inputs.iter().zip(ark_proofs.iter()) {
			let r = <Bn254 as Pairing>::ScalarField::rand(&mut rng);
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		domain::value_objects::circuit_constants::{BASE_VERIFICATION_COST, PER_INPUT_COST},
		infrastructure::storage::verification_keys,
	};
	use ark_bn254::Fr as Bn254Fr;
	use ark_ff::{BigInteger, PrimeField};
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
		let vk = verification_keys::transfer::get_vk();
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();
		let inputs = create_mock_inputs(5);

		// Create an invalid proof with wrong byte length
		let invalid_proof = Proof::new(alloc::vec![0u8; 10]);

		let result = Groth16Verifier::verify(&vk_wrapper, &inputs, &invalid_proof);
		assert!(result.is_err());
	}

	#[test]
	fn test_verify_detects_input_count_mismatch() {
		let vk = verification_keys::transfer::get_vk();
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
		let vk = verification_keys::transfer::get_vk();
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
		let vk = verification_keys::unshield::get_vk();
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
		let vk = verification_keys::disclosure::get_vk();
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
		let vk = verification_keys::transfer::get_vk();
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
		let vk = verification_keys::transfer::get_vk();
		let pvk = PreparedVerifyingKey::from(vk);

		// Wrong input count
		let inputs = create_mock_inputs(3);
		let proof = create_mock_proof();

		let result = Groth16Verifier::verify_with_prepared_vk(&pvk, &inputs, &proof);
		assert!(result.is_err());
	}

	#[test]
	fn test_verify_with_prepared_vk_invalid_proof() {
		let vk = verification_keys::unshield::get_vk();
		let pvk = PreparedVerifyingKey::from(vk);

		let inputs = create_mock_inputs(5);
		let invalid_proof = Proof::new(alloc::vec![0u8; 5]);

		let result = Groth16Verifier::verify_with_prepared_vk(&pvk, &inputs, &invalid_proof);
		assert!(result.is_err());
	}

	// batch_verify tests
	#[test]
	fn test_batch_verify_empty_arrays() {
		let vk = verification_keys::transfer::get_vk();
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		let result = Groth16Verifier::batch_verify(&vk_wrapper, &[], &[]);
		assert!(result.is_ok());
		assert!(result.unwrap());
	}

	#[test]
	fn test_batch_verify_mismatched_lengths() {
		let vk = verification_keys::transfer::get_vk();
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
		let vk = verification_keys::transfer::get_vk();
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
		let vk = verification_keys::transfer::get_vk();
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
		let vk = verification_keys::transfer::get_vk();
		let vk_wrapper = VerifyingKey::from_ark_vk(&vk).unwrap();

		let inputs = alloc::vec![create_mock_inputs(5), create_mock_inputs(5)];
		let proofs = alloc::vec![create_mock_proof(), Proof::new(alloc::vec![0u8; 3])];

		let result = Groth16Verifier::batch_verify(&vk_wrapper, &inputs, &proofs);
		assert!(result.is_err());
	}

	#[test]
	fn test_batch_verify_input_count_mismatch() {
		let vk = verification_keys::transfer::get_vk();
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
		let transfer_vk = verification_keys::transfer::get_vk();
		let transfer_wrapper = VerifyingKey::from_ark_vk(&transfer_vk).unwrap();
		assert!(transfer_wrapper.prepare().is_ok());

		// Unshield
		let unshield_vk = verification_keys::unshield::get_vk();
		let unshield_wrapper = VerifyingKey::from_ark_vk(&unshield_vk).unwrap();
		assert!(unshield_wrapper.prepare().is_ok());

		// Disclosure
		let disclosure_vk = verification_keys::disclosure::get_vk();
		let disclosure_wrapper = VerifyingKey::from_ark_vk(&disclosure_vk).unwrap();
		assert!(disclosure_wrapper.prepare().is_ok());
	}

	#[test]
	fn test_verify_and_batch_verify_consistency() {
		let vk = verification_keys::transfer::get_vk();
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

	/// Test de regresión para el circuito private_link.
	/// Verifica que la VK hardcodeada en `private_link.rs` sea compatible con el
	/// proving key del CDN (circuits.orbinum.io/v1).
	///
	/// Datos capturados de una ejecución real de test:24 (2026-03-07) con el
	/// proving key actual del CDN. Si este test falla, significa que el VK en
	/// `primitives/zk-verifier/src/infrastructure/storage/verification_keys/private_link.rs`
	/// está desincronizado respecto al CDN — ejecuta `scripts/sync-circuits/sync-circuit-artifacts.sh`
	/// y regenera el archivo Rust con `scripts/sync-circuits/generate-vk-rust.sh private_link`.
	#[test]
	fn test_real_private_link_proof_against_hardcoded_vk() {
		use ark_groth16::Proof as ArkProof;
		use ark_serialize::CanonicalDeserialize;

		// VK hardcodeada de la crate
		let ark_vk = verification_keys::get_private_link_vk();
		let pvk = PreparedVerifyingKey::from(ark_vk);

		// Proof comprimido (128 bytes) generado por compress_snarkjs_proof_wasm
		// Capturado de npm run test:24 en 2026-03-07
		let proof_hex = "94c177a4516a446219f11d948f431db57e540252a5dbac43081199cc72ffbd04f99df60b2fdd2cb1af7e4a919e10d00defbef63562047b6898f55949b19e5f0f7a83adb71ccdeed329353e190d28d0b5be46905e47574127d2959559bb8423a946dc13483ecaa0ff4c311f14848502660960f8ef5d842485f6a618e712a39982";
		let proof_bytes: alloc::vec::Vec<u8> = (0..proof_hex.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&proof_hex[i..i + 2], 16).unwrap())
			.collect();
		assert_eq!(proof_bytes.len(), 128, "Proof debe ser 128 bytes");

		// Public inputs en formato LE de 32 bytes
		// publicSignals[0] = commitment (LE hex)
		let input0_hex = "7a103a55f6a19a42c486303590f2836ecb306eb0c704c64136e1ebcab7842a16";
		// publicSignals[1] = call_hash_fe (LE hex)
		let input1_hex = "4344ebdae7f9670c9f148635ff6b7add38d30e679360b508bb44800dfdf38522";

		let mut input0 = [0u8; 32];
		let mut input1 = [0u8; 32];
		for i in 0..32 {
			input0[i] = u8::from_str_radix(&input0_hex[i * 2..i * 2 + 2], 16).unwrap();
			input1[i] = u8::from_str_radix(&input1_hex[i * 2..i * 2 + 2], 16).unwrap();
		}

		let public_inputs = PublicInputs::new(alloc::vec![input0, input1]);
		let inputs_fr = public_inputs
			.to_field_elements()
			.expect("Conversión Fr debe funcionar");

		// Deserializar el proof
		let ark_proof = ArkProof::<Bn254>::deserialize_compressed(&proof_bytes[..])
			.expect("Deserialización del proof debe funcionar");

		// Verificar
		let valid = Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &inputs_fr)
			.expect("verify_proof no debe retornar error de pairing");

		// Si falla aquí, el VK no coincide con el proving key del CDN
		// Si pasa, el bug es otro (e.g. problem en el path de runtime)
		assert!(valid, "El proof de private_link debe verificar contra la VK hardcodeada. Si falla, el VK en Rust NO coincide con el proving key del CDN.");
	}
}
