//! Abstract verification interface (Hexagonal Architecture port).

use crate::domain::value_objects::{Proof, PublicInputs, VerifierError, VerifyingKey};

/// Port for proof verification operations
///
/// This trait abstracts over different verification implementations,
/// allowing the domain layer to remain independent of specific cryptographic libraries.
pub trait VerifierPort {
	/// Verify a zero-knowledge proof
	///
	/// # Arguments
	/// * `vk` - Verification key for the circuit
	/// * `public_inputs` - Public inputs to the circuit
	/// * `proof` - The proof to verify
	///
	/// # Returns
	/// * `Ok(())` if proof is valid
	/// * `Err(VerifierError)` if proof is invalid or verification fails
	fn verify(
		&self,
		vk: &VerifyingKey,
		public_inputs: &PublicInputs,
		proof: &Proof,
	) -> Result<(), VerifierError>;

	/// Verify a proof with a prepared verifying key (optimized)
	///
	/// Prepared keys cache pairing computations for faster verification.
	fn verify_prepared(
		&self,
		prepared_vk: &ark_groth16::PreparedVerifyingKey<crate::Bn254>,
		public_inputs: &PublicInputs,
		proof: &Proof,
	) -> Result<(), VerifierError>;
}
