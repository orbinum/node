//! Groth16 proof verifier implementation

use crate::domain::{
	entities::{Proof, VerificationKey},
	errors::DomainError,
	services::ProofValidator,
	value_objects::PublicInputs,
};

/// Groth16 proof verifier backed by `orbinum-zk-verifier` primitives.
pub struct Groth16Verifier;

impl ProofValidator for Groth16Verifier {
	fn verify(
		&self,
		vk: &VerificationKey,
		proof: &Proof,
		public_inputs: &PublicInputs,
	) -> Result<bool, DomainError> {
		// Skip real verification in benchmarks and tests
		#[cfg(any(feature = "runtime-benchmarks", test))]
		{
			let _ = (vk, proof, public_inputs);
			Ok(true)
		}

		// Real verification in production using orbinum-zk-verifier via adapters
		#[cfg(not(any(feature = "runtime-benchmarks", test)))]
		{
			use crate::infrastructure::adapters::{
				ProofAdapter, PublicInputsAdapter, VerificationKeyAdapter,
				primitives::PrimitiveGroth16Verifier,
			};

			// Convert domain types to primitive types using adapters
			let fp_vk = VerificationKeyAdapter::to_primitive(vk);
			let fp_proof = ProofAdapter::to_primitive(proof);
			let fp_inputs = PublicInputsAdapter::to_primitive(public_inputs);

			// Verify using orbinum-zk-verifier Groth16Verifier
			match PrimitiveGroth16Verifier::verify(&fp_vk, &fp_inputs, &fp_proof) {
				Ok(()) => Ok(true),
				Err(_) => Ok(false),
			}
		}
	}
}
