//! Error Types
//!
//! Defines all errors that can occur during encrypted memo operations.

/// Errors for encrypted memo operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoError {
	/// Encrypted data is too short
	DataTooShort,
	/// Encrypted data is too long
	DataTooLong,
	/// Decryption failed (wrong key or tampered data)
	DecryptionFailed,
	/// Encryption failed
	EncryptionFailed,
	/// Invalid note data format
	InvalidNoteData,
	/// Commitment mismatch after decryption
	CommitmentMismatch,
	/// Invalid disclosure mask configuration
	InvalidDisclosureMask(&'static str),
	/// Invalid disclosed data format
	InvalidDisclosureData,
	/// Invalid disclosure proof
	InvalidProof(&'static str),
	/// Proof generation failed
	ProofGenerationFailed(&'static str),
	/// Witness calculation failed
	WitnessCalculationFailed(&'static str),
	/// Circuit constraints not satisfied
	CircuitUnsatisfied(&'static str),
	/// Invalid proving key format
	InvalidProvingKey(&'static str),
	/// Key loading failed
	KeyLoadingFailed(&'static str),
	/// Invalid field element conversion
	InvalidFieldElement(&'static str),
	/// Public signals validation failed
	InvalidPublicSignals(&'static str),
	/// WASM witness calculator loading failed
	WasmLoadFailed(&'static str),
}

impl core::fmt::Display for MemoError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::DataTooShort => write!(f, "Encrypted data is too short"),
			Self::DataTooLong => write!(f, "Encrypted data exceeds maximum allowed size"),
			Self::DecryptionFailed => write!(f, "Decryption failed - wrong key or tampered data"),
			Self::EncryptionFailed => write!(f, "Encryption operation failed"),
			Self::InvalidNoteData => write!(f, "Invalid note data format"),
			Self::CommitmentMismatch => write!(f, "Commitment mismatch after decryption"),
			Self::InvalidDisclosureMask(msg) => write!(f, "Invalid disclosure mask: {msg}"),
			Self::InvalidDisclosureData => write!(f, "Invalid disclosed data format"),
			Self::InvalidProof(msg) => write!(f, "Invalid disclosure proof: {msg}"),
			Self::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {msg}"),
			Self::WitnessCalculationFailed(msg) => {
				write!(f, "Witness calculation failed: {msg}")
			}
			Self::CircuitUnsatisfied(msg) => write!(f, "Circuit constraints not satisfied: {msg}"),
			Self::InvalidProvingKey(msg) => write!(f, "Invalid proving key (.ark format): {msg}"),
			Self::KeyLoadingFailed(msg) => write!(f, "Key loading failed: {msg}"),
			Self::InvalidFieldElement(msg) => write!(f, "Invalid field element conversion: {msg}"),
			Self::InvalidPublicSignals(msg) => write!(f, "Public signals validation failed: {msg}"),
			Self::WasmLoadFailed(msg) => {
				write!(f, "WASM witness calculator loading failed: {msg}")
			}
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for MemoError {}
