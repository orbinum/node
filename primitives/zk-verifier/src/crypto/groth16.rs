//! Groth16 verifier implementation
//!
//! This module provides the core verification logic for Groth16 proofs
//! using the BN254 elliptic curve.

use crate::core::{
	constants::{BASE_VERIFICATION_COST, PER_INPUT_COST},
	error::VerifierError,
	types::{Proof, PublicInputs, VerifyingKey},
};
use crate::Bn254;
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
}
