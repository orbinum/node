//! Domain error types.

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;

use core::fmt;

/// Errors that can occur during proof verification
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub enum VerifierError {
	/// The proof is invalid or malformed
	InvalidProof,
	/// The verifying key is invalid or malformed
	InvalidVerifyingKey,
	/// Public input is invalid
	InvalidPublicInput,
	/// Public input count mismatch
	InvalidPublicInputCount { expected: u32, got: u32 },
	/// Proof verification failed (proof is incorrect)
	VerificationFailed,
	/// Serialization/deserialization error
	SerializationError,
	/// Invalid proof size
	InvalidProofSize,
	/// Invalid verifying key size
	InvalidVKSize,
	/// Invalid circuit ID (not recognized)
	InvalidCircuitId(u8),
}

impl fmt::Display for VerifierError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			VerifierError::InvalidProof => write!(f, "Invalid proof"),
			VerifierError::InvalidVerifyingKey => write!(f, "Invalid verifying key"),
			VerifierError::InvalidPublicInput => write!(f, "Invalid public input"),
			VerifierError::InvalidPublicInputCount { expected, got } => {
				write!(
					f,
					"Invalid public input count: expected {expected}, got {got}"
				)
			}
			VerifierError::VerificationFailed => write!(f, "Verification failed"),
			VerifierError::SerializationError => write!(f, "Serialization error"),
			VerifierError::InvalidProofSize => write!(f, "Invalid proof size"),
			VerifierError::InvalidVKSize => write!(f, "Invalid verifying key size"),
			VerifierError::InvalidCircuitId(id) => write!(f, "Invalid circuit ID: {id}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for VerifierError {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_error_equality_and_clone() {
		let a = VerifierError::InvalidProof;
		let b = a.clone();
		assert_eq!(a, b);

		let c = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 3,
		};
		let d = c.clone();
		assert_eq!(c, d);
	}

	#[test]
	fn test_display_messages() {
		assert_eq!(VerifierError::InvalidProof.to_string(), "Invalid proof");
		assert_eq!(
			VerifierError::InvalidVerifyingKey.to_string(),
			"Invalid verifying key"
		);
		assert_eq!(
			VerifierError::InvalidPublicInput.to_string(),
			"Invalid public input"
		);
		assert_eq!(
			VerifierError::VerificationFailed.to_string(),
			"Verification failed"
		);
		assert_eq!(
			VerifierError::SerializationError.to_string(),
			"Serialization error"
		);
		assert_eq!(
			VerifierError::InvalidProofSize.to_string(),
			"Invalid proof size"
		);
		assert_eq!(
			VerifierError::InvalidVKSize.to_string(),
			"Invalid verifying key size"
		);
	}

	#[test]
	fn test_display_dynamic_messages() {
		let msg = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 2,
		}
		.to_string();
		assert_eq!(msg, "Invalid public input count: expected 5, got 2");

		let msg = VerifierError::InvalidCircuitId(9).to_string();
		assert_eq!(msg, "Invalid circuit ID: 9");
	}
}
