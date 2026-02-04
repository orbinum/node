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

// Note: The actual implementation will be in infrastructure layer
// using fp-zk-verifier crate, as it requires cryptographic operations
// This trait defines the domain contract
