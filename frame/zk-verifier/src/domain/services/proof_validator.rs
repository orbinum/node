//! Proof validator service

use crate::domain::{
	entities::{Proof, VerificationKey},
	errors::DomainError,
	value_objects::PublicInputs,
};

/// Trait for validating and verifying proofs
pub trait ProofValidator {
	/// Verify a zero-knowledge proof
	fn verify(
		&self,
		vk: &VerificationKey,
		proof: &Proof,
		public_inputs: &PublicInputs,
	) -> Result<bool, DomainError>;
}

// Note: The concrete implementation lives in the infrastructure layer
// (e.g. Groth16 verifier + adapters to runtime/primitives cryptography).
// This trait is the stable domain contract.
