//! # Verify Proof Use Case
//!
//! Application use case for verifying ZK proofs.

use crate::domain::{
	ports::VerifierPort,
	services::ProofValidator,
	value_objects::{Proof, PublicInputs, VerifierError, VerifyingKey},
};

/// Use case for proof verification
pub struct VerifyProofUseCase<V: VerifierPort> {
	verifier: V,
}

impl<V: VerifierPort> VerifyProofUseCase<V> {
	/// Create new use case instance
	pub fn new(verifier: V) -> Self {
		Self { verifier }
	}

	/// Execute proof verification
	///
	/// Validates inputs and delegates to verifier implementation.
	pub fn execute(
		&self,
		vk: &VerifyingKey,
		public_inputs: &PublicInputs,
		proof: &Proof,
		expected_input_count: usize,
	) -> Result<(), VerifierError> {
		// Domain validation
		ProofValidator::validate_input_count(public_inputs, expected_input_count)?;
		ProofValidator::validate_proof_structure(proof.as_bytes())?;
		ProofValidator::validate_vk_structure(vk.as_bytes())?;

		// Delegate to infrastructure
		self.verifier.verify(vk, public_inputs, proof)
	}

	/// Execute proof verification with prepared VK (optimized)
	pub fn execute_prepared(
		&self,
		prepared_vk: &ark_groth16::PreparedVerifyingKey<crate::Bn254>,
		public_inputs: &PublicInputs,
		proof: &Proof,
		expected_input_count: usize,
	) -> Result<(), VerifierError> {
		// Domain validation
		ProofValidator::validate_input_count(public_inputs, expected_input_count)?;
		ProofValidator::validate_proof_structure(proof.as_bytes())?;

		// Delegate to infrastructure
		self.verifier
			.verify_prepared(prepared_vk, public_inputs, proof)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::rc::Rc;
	use ark_bn254::{Fr as Bn254Fr, G1Affine, G2Affine};
	use ark_ec::AffineRepr;
	use ark_ff::{BigInteger, PrimeField};
	use ark_groth16::PreparedVerifyingKey;
	use ark_serialize::CanonicalSerialize;
	use core::cell::RefCell;

	// Mock verifier that tracks calls using Rc<RefCell<>>
	#[derive(Clone)]
	struct MockVerifier {
		should_succeed: bool,
		verify_called: Rc<RefCell<usize>>,
		verify_prepared_called: Rc<RefCell<usize>>,
	}

	impl MockVerifier {
		fn new(should_succeed: bool) -> Self {
			Self {
				should_succeed,
				verify_called: Rc::new(RefCell::new(0)),
				verify_prepared_called: Rc::new(RefCell::new(0)),
			}
		}

		fn verify_call_count(&self) -> usize {
			*self.verify_called.borrow()
		}

		fn verify_prepared_call_count(&self) -> usize {
			*self.verify_prepared_called.borrow()
		}
	}

	impl VerifierPort for MockVerifier {
		fn verify(
			&self,
			_vk: &VerifyingKey,
			_public_inputs: &PublicInputs,
			_proof: &Proof,
		) -> Result<(), VerifierError> {
			*self.verify_called.borrow_mut() += 1;
			if self.should_succeed {
				Ok(())
			} else {
				Err(VerifierError::VerificationFailed)
			}
		}

		fn verify_prepared(
			&self,
			_prepared_vk: &PreparedVerifyingKey<crate::Bn254>,
			_public_inputs: &PublicInputs,
			_proof: &Proof,
		) -> Result<(), VerifierError> {
			*self.verify_prepared_called.borrow_mut() += 1;
			if self.should_succeed {
				Ok(())
			} else {
				Err(VerifierError::VerificationFailed)
			}
		}
	}

	// Helper: Create valid mock proof
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

	// Helper: Create mock public inputs
	fn create_mock_inputs(count: usize) -> PublicInputs {
		let mut inputs = alloc::vec::Vec::new();
		for i in 0..count {
			let field = Bn254Fr::from(i as u64 + 1);
			let bigint = field.into_bigint();
			let bytes_vec = bigint.to_bytes_be();
			let mut bytes = [0u8; 32];
			let start = 32 - bytes_vec.len();
			bytes[start..].copy_from_slice(&bytes_vec);
			inputs.push(bytes);
		}
		PublicInputs::new(inputs)
	}

	// Helper: Create mock VK
	fn create_mock_vk() -> VerifyingKey {
		use crate::infrastructure::storage::verification_keys;
		let vk = verification_keys::transfer::get_vk();
		VerifyingKey::from_ark_vk(&vk).unwrap()
	}

	// Helper: Create mock prepared VK
	fn create_mock_prepared_vk() -> PreparedVerifyingKey<crate::Bn254> {
		use crate::infrastructure::storage::verification_keys;
		let vk = verification_keys::transfer::get_vk();
		PreparedVerifyingKey::from(vk)
	}

	// execute() tests - successful verification
	#[test]
	fn test_execute_success() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = use_case.execute(&vk, &inputs, &proof, 5);
		assert!(result.is_ok());
		assert_eq!(mock_verifier.verify_call_count(), 1);
	}

	#[test]
	fn test_execute_delegates_to_verifier() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let _ = use_case.execute(&vk, &inputs, &proof, 5);
		assert_eq!(mock_verifier.verify_call_count(), 1);
		assert_eq!(mock_verifier.verify_prepared_call_count(), 0);
	}

	// execute() tests - validation failures
	#[test]
	fn test_execute_fails_with_wrong_input_count() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(3); // Create 3 inputs
		let proof = create_mock_proof();

		let result = use_case.execute(&vk, &inputs, &proof, 5); // Expect 5
		assert!(result.is_err());
		match result {
			Err(VerifierError::InvalidPublicInputCount { .. }) => {
				// Expected
			}
			_ => panic!("Expected InvalidPublicInputCount error"),
		}
		// Verifier should not be called due to validation failure
		assert_eq!(mock_verifier.verify_call_count(), 0);
	}

	#[test]
	fn test_execute_fails_with_zero_inputs_expected_nonzero() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier);

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(0);
		let proof = create_mock_proof();

		let result = use_case.execute(&vk, &inputs, &proof, 5);
		assert!(result.is_err());
	}

	#[test]
	fn test_execute_fails_with_invalid_proof_structure() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(5);
		let invalid_proof = Proof::new(alloc::vec![0u8; 5]); // Too short

		let result = use_case.execute(&vk, &inputs, &invalid_proof, 5);
		assert!(result.is_err());
		match result {
			Err(VerifierError::InvalidProof) => {
				// Expected
			}
			_ => panic!("Expected InvalidProof error"),
		}
		assert_eq!(mock_verifier.verify_call_count(), 0);
	}

	#[test]
	fn test_execute_fails_with_empty_proof() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(5);
		let empty_proof = Proof::new(alloc::vec![]);

		let result = use_case.execute(&vk, &inputs, &empty_proof, 5);
		assert!(result.is_err());
		assert_eq!(mock_verifier.verify_call_count(), 0);
	}

	#[test]
	fn test_execute_fails_with_invalid_vk_structure() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let invalid_vk = VerifyingKey::new(alloc::vec![0u8; 10]); // Too short
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = use_case.execute(&invalid_vk, &inputs, &proof, 5);
		assert!(result.is_err());
		match result {
			Err(VerifierError::InvalidVerifyingKey) => {
				// Expected
			}
			_ => panic!("Expected InvalidVerifyingKey error"),
		}
		assert_eq!(mock_verifier.verify_call_count(), 0);
	}

	#[test]
	fn test_execute_fails_with_empty_vk() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let empty_vk = VerifyingKey::new(alloc::vec![]);
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = use_case.execute(&empty_vk, &inputs, &proof, 5);
		assert!(result.is_err());
		assert_eq!(mock_verifier.verify_call_count(), 0);
	}

	// execute() tests - verifier failures
	#[test]
	fn test_execute_propagates_verifier_failure() {
		let mock_verifier = MockVerifier::new(false); // Will fail
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = use_case.execute(&vk, &inputs, &proof, 5);
		assert!(result.is_err());
		match result {
			Err(VerifierError::VerificationFailed) => {
				// Expected
			}
			_ => panic!("Expected VerificationFailed error"),
		}
		assert_eq!(mock_verifier.verify_call_count(), 1);
	}

	// execute() tests - edge cases
	#[test]
	fn test_execute_with_zero_expected_inputs() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(0);
		let proof = create_mock_proof();

		let result = use_case.execute(&vk, &inputs, &proof, 0);
		assert!(result.is_ok());
		assert_eq!(mock_verifier.verify_call_count(), 1);
	}

	#[test]
	fn test_execute_with_large_input_count() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(20);
		let proof = create_mock_proof();

		let result = use_case.execute(&vk, &inputs, &proof, 20);
		assert!(result.is_ok());
		assert_eq!(mock_verifier.verify_call_count(), 1);
	}

	#[test]
	fn test_execute_multiple_calls() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		// Call multiple times
		let _ = use_case.execute(&vk, &inputs, &proof, 5);
		let _ = use_case.execute(&vk, &inputs, &proof, 5);
		let _ = use_case.execute(&vk, &inputs, &proof, 5);

		assert_eq!(mock_verifier.verify_call_count(), 3);
	}

	// execute_prepared() tests - successful verification
	#[test]
	fn test_execute_prepared_success() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 5);
		assert!(result.is_ok());
		assert_eq!(mock_verifier.verify_prepared_call_count(), 1);
	}

	#[test]
	fn test_execute_prepared_delegates_to_verifier() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let _ = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 5);
		assert_eq!(mock_verifier.verify_call_count(), 0);
		assert_eq!(mock_verifier.verify_prepared_call_count(), 1);
	}

	// execute_prepared() tests - validation failures
	#[test]
	fn test_execute_prepared_fails_with_wrong_input_count() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(3);
		let proof = create_mock_proof();

		let result = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 5);
		assert!(result.is_err());
		assert_eq!(mock_verifier.verify_prepared_call_count(), 0);
	}

	#[test]
	fn test_execute_prepared_fails_with_invalid_proof() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(5);
		let invalid_proof = Proof::new(alloc::vec![0u8; 3]);

		let result = use_case.execute_prepared(&prepared_vk, &inputs, &invalid_proof, 5);
		assert!(result.is_err());
		assert_eq!(mock_verifier.verify_prepared_call_count(), 0);
	}

	#[test]
	fn test_execute_prepared_fails_with_empty_proof() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(5);
		let empty_proof = Proof::new(alloc::vec![]);

		let result = use_case.execute_prepared(&prepared_vk, &inputs, &empty_proof, 5);
		assert!(result.is_err());
		assert_eq!(mock_verifier.verify_prepared_call_count(), 0);
	}

	// execute_prepared() tests - verifier failures
	#[test]
	fn test_execute_prepared_propagates_verifier_failure() {
		let mock_verifier = MockVerifier::new(false);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let result = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 5);
		assert!(result.is_err());
		match result {
			Err(VerifierError::VerificationFailed) => {
				// Expected
			}
			_ => panic!("Expected VerificationFailed error"),
		}
		assert_eq!(mock_verifier.verify_prepared_call_count(), 1);
	}

	// execute_prepared() tests - edge cases
	#[test]
	fn test_execute_prepared_with_zero_expected_inputs() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(0);
		let proof = create_mock_proof();

		let result = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 0);
		assert!(result.is_ok());
		assert_eq!(mock_verifier.verify_prepared_call_count(), 1);
	}

	#[test]
	fn test_execute_prepared_with_large_input_count() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(20);
		let proof = create_mock_proof();

		let result = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 20);
		assert!(result.is_ok());
		assert_eq!(mock_verifier.verify_prepared_call_count(), 1);
	}

	#[test]
	fn test_execute_prepared_multiple_calls() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let _ = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 5);
		let _ = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 5);
		let _ = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 5);

		assert_eq!(mock_verifier.verify_prepared_call_count(), 3);
	}

	// Comparison tests - execute vs execute_prepared
	#[test]
	fn test_execute_and_execute_prepared_are_independent() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let prepared_vk = create_mock_prepared_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		let _ = use_case.execute(&vk, &inputs, &proof, 5);
		let _ = use_case.execute_prepared(&prepared_vk, &inputs, &proof, 5);

		assert_eq!(mock_verifier.verify_call_count(), 1);
		assert_eq!(mock_verifier.verify_prepared_call_count(), 1);
	}

	// Use case construction tests
	#[test]
	fn test_new_use_case() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier);
		// Just verify construction doesn't panic
		let _ = use_case;
	}

	#[test]
	fn test_use_case_can_be_reused() {
		let mock_verifier = MockVerifier::new(true);
		let use_case = VerifyProofUseCase::new(mock_verifier.clone());

		let vk = create_mock_vk();
		let inputs = create_mock_inputs(5);
		let proof = create_mock_proof();

		// Multiple uses with different data
		let _ = use_case.execute(&vk, &inputs, &proof, 5);
		let _ = use_case.execute(&vk, &inputs, &proof, 5);

		assert_eq!(mock_verifier.verify_call_count(), 2);
	}
}
