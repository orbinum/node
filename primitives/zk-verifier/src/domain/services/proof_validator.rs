//! Validation service for proof structure and public inputs.

use crate::domain::value_objects::{PublicInputs, VerifierError};

/// Domain service for proof validation
pub struct ProofValidator;

impl ProofValidator {
	/// Validate public inputs count matches expected for circuit
	pub fn validate_input_count(
		inputs: &PublicInputs,
		expected: usize,
	) -> Result<(), VerifierError> {
		if inputs.len() != expected {
			return Err(VerifierError::InvalidPublicInputCount {
				expected,
				got: inputs.len(),
			});
		}
		Ok(())
	}

	/// Validate proof structure (basic checks)
	pub fn validate_proof_structure(proof_bytes: &[u8]) -> Result<(), VerifierError> {
		// Groth16 proof should be ~200 bytes
		// G1: 32 bytes (compressed)
		// G2: 64 bytes (compressed)
		// G1: 32 bytes (compressed)
		// Total: ~128 bytes minimum
		if proof_bytes.len() < 100 {
			return Err(VerifierError::InvalidProof);
		}
		Ok(())
	}

	/// Validate verifying key structure
	pub fn validate_vk_structure(vk_bytes: &[u8]) -> Result<(), VerifierError> {
		// VK should have minimum size based on circuit structure
		if vk_bytes.len() < 200 {
			return Err(VerifierError::InvalidVerifyingKey);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::vec;

	#[test]
	fn test_validate_input_count_valid() {
		let inputs = PublicInputs::new(vec![[0u8; 32], [1u8; 32]]);
		assert!(ProofValidator::validate_input_count(&inputs, 2).is_ok());
	}

	#[test]
	fn test_validate_input_count_mismatch() {
		let inputs = PublicInputs::new(vec![[0u8; 32], [1u8; 32]]);
		let result = ProofValidator::validate_input_count(&inputs, 3);
		assert!(result.is_err());

		match result {
			Err(VerifierError::InvalidPublicInputCount { expected, got }) => {
				assert_eq!(expected, 3);
				assert_eq!(got, 2);
			}
			_ => panic!("Expected InvalidPublicInputCount error"),
		}
	}

	#[test]
	fn test_validate_input_count_empty() {
		let inputs = PublicInputs::new(vec![]);
		assert!(ProofValidator::validate_input_count(&inputs, 0).is_ok());
		assert!(ProofValidator::validate_input_count(&inputs, 1).is_err());
	}

	#[test]
	fn test_validate_input_count_many_inputs() {
		let inputs = PublicInputs::new(vec![[0u8; 32]; 32]);
		assert!(ProofValidator::validate_input_count(&inputs, 32).is_ok());
		assert!(ProofValidator::validate_input_count(&inputs, 31).is_err());
		assert!(ProofValidator::validate_input_count(&inputs, 33).is_err());
	}

	#[test]
	fn test_validate_proof_structure_too_small() {
		assert!(ProofValidator::validate_proof_structure(&[0u8; 50]).is_err());
		assert!(ProofValidator::validate_proof_structure(&[0u8; 99]).is_err());
	}

	#[test]
	fn test_validate_proof_structure_edge_case() {
		// Exactly at boundary
		assert!(ProofValidator::validate_proof_structure(&[0u8; 100]).is_ok());
	}

	#[test]
	fn test_validate_proof_structure_valid_sizes() {
		assert!(ProofValidator::validate_proof_structure(&[0u8; 128]).is_ok());
		assert!(ProofValidator::validate_proof_structure(&[0u8; 192]).is_ok());
		assert!(ProofValidator::validate_proof_structure(&[0u8; 256]).is_ok());
	}

	#[test]
	fn test_validate_proof_structure_empty() {
		assert!(ProofValidator::validate_proof_structure(&[]).is_err());
	}

	#[test]
	fn test_validate_vk_structure_too_small() {
		assert!(ProofValidator::validate_vk_structure(&[0u8; 100]).is_err());
		assert!(ProofValidator::validate_vk_structure(&[0u8; 199]).is_err());
	}

	#[test]
	fn test_validate_vk_structure_edge_case() {
		// Exactly at boundary
		assert!(ProofValidator::validate_vk_structure(&[0u8; 200]).is_ok());
	}

	#[test]
	fn test_validate_vk_structure_valid_sizes() {
		assert!(ProofValidator::validate_vk_structure(&vec![0u8; 300]).is_ok());
		assert!(ProofValidator::validate_vk_structure(&vec![0u8; 500]).is_ok());
		assert!(ProofValidator::validate_vk_structure(&vec![0u8; 1024]).is_ok());
	}

	#[test]
	fn test_validate_vk_structure_empty() {
		assert!(ProofValidator::validate_vk_structure(&[]).is_err());
	}
}
