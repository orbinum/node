//! # Verification Result DTO
//!
//! Data Transfer Object for verification results.

use crate::domain::value_objects::VerifierError;

/// Result of proof verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
	/// Whether the proof is valid
	pub is_valid: bool,
	/// Error if verification failed
	pub error: Option<VerifierError>,
}

impl VerificationResult {
	/// Create successful verification result
	pub fn success() -> Self {
		Self {
			is_valid: true,
			error: None,
		}
	}

	/// Create failed verification result
	pub fn failure(error: VerifierError) -> Self {
		Self {
			is_valid: false,
			error: Some(error),
		}
	}

	/// Convert from Result
	pub fn from_result(result: Result<(), VerifierError>) -> Self {
		match result {
			Ok(()) => Self::success(),
			Err(e) => Self::failure(e),
		}
	}

	/// Convert to Result
	pub fn to_result(self) -> Result<(), VerifierError> {
		if self.is_valid {
			Ok(())
		} else {
			Err(self.error.unwrap_or(VerifierError::InvalidProof))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::format;

	// success() tests
	#[test]
	fn test_success_result() {
		let result = VerificationResult::success();
		assert!(result.is_valid);
		assert!(result.error.is_none());
	}

	#[test]
	fn test_success_has_no_error() {
		let result = VerificationResult::success();
		assert_eq!(result.error, None);
	}

	#[test]
	fn test_success_is_valid() {
		let result = VerificationResult::success();
		assert!(result.is_valid);
	}

	// failure() tests
	#[test]
	fn test_failure_result() {
		let result = VerificationResult::failure(VerifierError::InvalidProof);
		assert!(!result.is_valid);
		assert!(result.error.is_some());
	}

	#[test]
	fn test_failure_is_not_valid() {
		let result = VerificationResult::failure(VerifierError::VerificationFailed);
		assert!(!result.is_valid);
	}

	#[test]
	fn test_failure_contains_error() {
		let result = VerificationResult::failure(VerifierError::InvalidProof);
		assert_eq!(result.error, Some(VerifierError::InvalidProof));
	}

	#[test]
	fn test_failure_with_different_errors() {
		let errors = [
			VerifierError::InvalidProof,
			VerifierError::VerificationFailed,
			VerifierError::InvalidVerifyingKey,
			VerifierError::InvalidPublicInput,
			VerifierError::SerializationError,
			VerifierError::InvalidProofSize,
			VerifierError::InvalidVKSize,
		];

		for error in errors {
			let result = VerificationResult::failure(error.clone());
			assert!(!result.is_valid);
			assert_eq!(result.error, Some(error));
		}
	}

	#[test]
	fn test_failure_with_invalid_public_input_count() {
		let error = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 3,
		};
		let result = VerificationResult::failure(error.clone());
		assert!(!result.is_valid);
		assert_eq!(result.error, Some(error));
	}

	#[test]
	fn test_failure_with_invalid_circuit_id() {
		let error = VerifierError::InvalidCircuitId(99);
		let result = VerificationResult::failure(error.clone());
		assert!(!result.is_valid);
		assert_eq!(result.error, Some(error));
	}

	// from_result() tests
	#[test]
	fn test_from_result() {
		let result = VerificationResult::from_result(Ok(()));
		assert!(result.is_valid);

		let result = VerificationResult::from_result(Err(VerifierError::InvalidProof));
		assert!(!result.is_valid);
	}

	#[test]
	fn test_from_result_ok() {
		let result = VerificationResult::from_result(Ok(()));
		assert!(result.is_valid);
		assert!(result.error.is_none());
	}

	#[test]
	fn test_from_result_err() {
		let result = VerificationResult::from_result(Err(VerifierError::VerificationFailed));
		assert!(!result.is_valid);
		assert_eq!(result.error, Some(VerifierError::VerificationFailed));
	}

	#[test]
	fn test_from_result_preserves_error_type() {
		let error = VerifierError::InvalidPublicInputCount {
			expected: 10,
			got: 5,
		};
		let result = VerificationResult::from_result(Err(error.clone()));
		assert_eq!(result.error, Some(error));
	}

	#[test]
	fn test_from_result_multiple_error_types() {
		let errors = [
			VerifierError::InvalidProof,
			VerifierError::InvalidVerifyingKey,
			VerifierError::SerializationError,
		];

		for error in errors {
			let result = VerificationResult::from_result(Err(error.clone()));
			assert!(!result.is_valid);
			assert_eq!(result.error, Some(error));
		}
	}

	// to_result() tests
	#[test]
	fn test_to_result_success() {
		let verification = VerificationResult::success();
		let result = verification.to_result();
		assert!(result.is_ok());
	}

	#[test]
	fn test_to_result_failure() {
		let verification = VerificationResult::failure(VerifierError::InvalidProof);
		let result = verification.to_result();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), VerifierError::InvalidProof);
	}

	#[test]
	fn test_to_result_preserves_error() {
		let error = VerifierError::VerificationFailed;
		let verification = VerificationResult::failure(error.clone());
		let result = verification.to_result();
		match result {
			Err(e) => assert_eq!(e, error),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn test_to_result_with_none_error_uses_default() {
		// Create invalid result without error (edge case)
		let verification = VerificationResult {
			is_valid: false,
			error: None,
		};
		let result = verification.to_result();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), VerifierError::InvalidProof);
	}

	#[test]
	fn test_to_result_multiple_error_types() {
		let errors = [
			VerifierError::InvalidProof,
			VerifierError::InvalidVerifyingKey,
			VerifierError::InvalidPublicInput,
		];

		for error in errors {
			let verification = VerificationResult::failure(error.clone());
			let result = verification.to_result();
			assert!(result.is_err());
			assert_eq!(result.unwrap_err(), error);
		}
	}

	// Roundtrip tests
	#[test]
	fn test_from_result_to_result_roundtrip_ok() {
		let original: Result<(), VerifierError> = Ok(());
		let verification = VerificationResult::from_result(original);
		let recovered = verification.to_result();
		assert!(recovered.is_ok());
	}

	#[test]
	fn test_from_result_to_result_roundtrip_err() {
		let original: Result<(), VerifierError> = Err(VerifierError::InvalidProof);
		let verification = VerificationResult::from_result(original.clone());
		let recovered = verification.to_result();
		assert_eq!(recovered, original);
	}

	#[test]
	fn test_success_to_result_roundtrip() {
		let verification = VerificationResult::success();
		let result = verification.to_result();
		let back = VerificationResult::from_result(result);
		assert!(back.is_valid);
		assert!(back.error.is_none());
	}

	#[test]
	fn test_failure_to_result_roundtrip() {
		let error = VerifierError::VerificationFailed;
		let verification = VerificationResult::failure(error.clone());
		let result = verification.to_result();
		let back = VerificationResult::from_result(result);
		assert!(!back.is_valid);
		assert_eq!(back.error, Some(error));
	}

	// Clone and PartialEq tests
	#[test]
	fn test_clone_success() {
		let original = VerificationResult::success();
		let cloned = original.clone();
		assert_eq!(original, cloned);
	}

	#[test]
	fn test_clone_failure() {
		let original = VerificationResult::failure(VerifierError::InvalidProof);
		let cloned = original.clone();
		assert_eq!(original, cloned);
	}

	#[test]
	fn test_equality_success() {
		let result1 = VerificationResult::success();
		let result2 = VerificationResult::success();
		assert_eq!(result1, result2);
	}

	#[test]
	fn test_equality_failure_same_error() {
		let result1 = VerificationResult::failure(VerifierError::InvalidProof);
		let result2 = VerificationResult::failure(VerifierError::InvalidProof);
		assert_eq!(result1, result2);
	}

	#[test]
	fn test_inequality_different_validity() {
		let result1 = VerificationResult::success();
		let result2 = VerificationResult::failure(VerifierError::InvalidProof);
		assert_ne!(result1, result2);
	}

	#[test]
	fn test_inequality_different_errors() {
		let result1 = VerificationResult::failure(VerifierError::InvalidProof);
		let result2 = VerificationResult::failure(VerifierError::VerificationFailed);
		assert_ne!(result1, result2);
	}

	#[test]
	fn test_equality_with_invalid_input_count() {
		let error1 = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 3,
		};
		let error2 = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 3,
		};
		let result1 = VerificationResult::failure(error1);
		let result2 = VerificationResult::failure(error2);
		assert_eq!(result1, result2);
	}

	#[test]
	fn test_inequality_with_different_input_counts() {
		let error1 = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 3,
		};
		let error2 = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 4,
		};
		let result1 = VerificationResult::failure(error1);
		let result2 = VerificationResult::failure(error2);
		assert_ne!(result1, result2);
	}

	// Edge cases
	#[test]
	fn test_manual_construction_valid() {
		let result = VerificationResult {
			is_valid: true,
			error: None,
		};
		assert!(result.is_valid);
		assert!(result.error.is_none());
	}

	#[test]
	fn test_manual_construction_invalid() {
		let result = VerificationResult {
			is_valid: false,
			error: Some(VerifierError::InvalidProof),
		};
		assert!(!result.is_valid);
		assert!(result.error.is_some());
	}

	#[test]
	fn test_inconsistent_state_valid_with_error() {
		// Edge case: valid but has error (inconsistent but allowed by struct)
		let result = VerificationResult {
			is_valid: true,
			error: Some(VerifierError::InvalidProof),
		};
		// to_result() should return Ok because is_valid is true
		let converted = result.to_result();
		assert!(converted.is_ok());
	}

	#[test]
	fn test_multiple_conversions() {
		let error = VerifierError::InvalidProof;

		// Start with Result -> DTO -> Result -> DTO
		let result1: Result<(), VerifierError> = Err(error.clone());
		let dto1 = VerificationResult::from_result(result1);
		let result2 = dto1.clone().to_result();
		let dto2 = VerificationResult::from_result(result2);

		assert_eq!(dto1, dto2);
		assert!(!dto2.is_valid);
		assert_eq!(dto2.error, Some(error));
	}

	// Debug trait test
	#[test]
	fn test_debug_format() {
		let result = VerificationResult::success();
		let debug_str = format!("{result:?}");
		assert!(debug_str.contains("VerificationResult"));
		assert!(debug_str.contains("is_valid"));
		assert!(debug_str.contains("true"));
	}

	#[test]
	fn test_debug_format_with_error() {
		let result = VerificationResult::failure(VerifierError::InvalidProof);
		let debug_str = format!("{result:?}");
		assert!(debug_str.contains("VerificationResult"));
		assert!(debug_str.contains("false"));
		assert!(debug_str.contains("InvalidProof"));
	}
}
