//! Domain errors
//!
//! Business logic errors that are independent of the framework.

/// Domain-level errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
	/// Invalid commitment format or value
	InvalidCommitment,
	/// Invalid nullifier format or value
	InvalidNullifier,
	/// Nullifier has already been used (double-spend attempt)
	NullifierAlreadyUsed,
	/// Note value is invalid (e.g., zero or negative)
	InvalidNoteValue,
	/// Asset ID is not valid or not registered
	InvalidAssetId,
	/// Asset is not verified for shielded operations
	AssetNotVerified,
	/// Encrypted memo size exceeds maximum
	InvalidMemoSize,
	/// Encrypted memo is malformed
	MalformedMemo,
	/// Merkle root is not in the set of known roots
	UnknownMerkleRoot,
	/// Merkle proof verification failed
	InvalidMerkleProof,
	/// Zero-knowledge proof verification failed
	InvalidZkProof,
	/// Insufficient balance in the pool for this operation
	InsufficientPoolBalance,
	/// Operation would result in invalid state
	InvalidState,
	/// Generic domain validation error
	ValidationError(&'static str),
}

impl DomainError {
	/// Convert domain error to a dispatch error message
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::InvalidCommitment => "Invalid commitment",
			Self::InvalidNullifier => "Invalid nullifier",
			Self::NullifierAlreadyUsed => "Nullifier already used",
			Self::InvalidNoteValue => "Invalid note value",
			Self::InvalidAssetId => "Invalid asset ID",
			Self::AssetNotVerified => "Asset not verified",
			Self::InvalidMemoSize => "Invalid memo size",
			Self::MalformedMemo => "Malformed memo",
			Self::UnknownMerkleRoot => "Unknown Merkle root",
			Self::InvalidMerkleProof => "Invalid Merkle proof",
			Self::InvalidZkProof => "Invalid ZK proof",
			Self::InsufficientPoolBalance => "Insufficient pool balance",
			Self::InvalidState => "Invalid state",
			Self::ValidationError(msg) => msg,
		}
	}
}

impl core::fmt::Display for DomainError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{}", self.as_str())
	}
}

/// Result type for domain operations
pub type DomainResult<T> = Result<T, DomainError>;
