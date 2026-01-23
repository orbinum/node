//! # Errors
//!
//! Error types for zero-knowledge primitive operations.

/// Errors that can occur in ZK primitive operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveError {
	/// Invalid field element (out of range or malformed)
	InvalidFieldElement,
	/// Merkle proof verification failed
	MerkleProofVerificationFailed,
	/// Invalid note data
	InvalidNoteData,
	/// Poseidon hash failed
	PoseidonHashFailed,
	/// Invalid path length
	InvalidPathLength,
	/// Tree depth exceeded maximum
	TreeDepthExceeded,
}

impl PrimitiveError {
	/// Returns a static string describing the error
	pub fn as_str(&self) -> &'static str {
		match self {
			PrimitiveError::InvalidFieldElement => "Invalid field element",
			PrimitiveError::MerkleProofVerificationFailed => "Merkle proof verification failed",
			PrimitiveError::InvalidNoteData => "Invalid note data",
			PrimitiveError::PoseidonHashFailed => "Poseidon hash failed",
			PrimitiveError::InvalidPathLength => "Invalid path length",
			PrimitiveError::TreeDepthExceeded => "Tree depth exceeded maximum",
		}
	}
}

#[cfg(feature = "std")]
impl core::fmt::Display for PrimitiveError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{}", self.as_str())
	}
}

#[cfg(feature = "std")]
impl std::error::Error for PrimitiveError {}
