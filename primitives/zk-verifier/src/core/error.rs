//! # Error Types
//!
//! Error types for ZK proof verification.

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;
#[cfg(feature = "substrate")]
use sp_runtime::RuntimeDebug;

use core::fmt;

/// Errors that can occur during proof verification
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo, RuntimeDebug))]
pub enum VerifierError {
	/// The proof is invalid or malformed
	InvalidProof,
	/// The verifying key is invalid or malformed
	InvalidVerifyingKey,
	/// Public input is invalid
	InvalidPublicInput,
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
