//! Error types for encrypted memo operations.

/// All errors that can occur during encrypted memo operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoError {
	/// Encrypted data is too short (below minimum size)
	DataTooShort,
	/// Encrypted data exceeds maximum allowed size
	DataTooLong,
	/// Decryption failed — wrong key or tampered data
	DecryptionFailed,
	/// Encryption operation failed
	EncryptionFailed,
	/// Invalid note data format during deserialization
	InvalidNoteData,
	/// Commitment mismatch detected after decryption
	CommitmentMismatch,
	/// Invalid disclosure mask configuration
	InvalidDisclosureMask(&'static str),
	/// Invalid disclosed data format
	InvalidDisclosureData,
	/// Invalid or inconsistent disclosure proof
	InvalidProof(&'static str),
}

impl core::fmt::Display for MemoError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::DataTooShort => write!(f, "Encrypted data is too short"),
			Self::DataTooLong => write!(f, "Encrypted data exceeds maximum allowed size"),
			Self::DecryptionFailed => write!(f, "Decryption failed — wrong key or tampered data"),
			Self::EncryptionFailed => write!(f, "Encryption operation failed"),
			Self::InvalidNoteData => write!(f, "Invalid note data format"),
			Self::CommitmentMismatch => write!(f, "Commitment mismatch after decryption"),
			Self::InvalidDisclosureMask(msg) => write!(f, "Invalid disclosure mask: {msg}"),
			Self::InvalidDisclosureData => write!(f, "Invalid disclosed data format"),
			Self::InvalidProof(msg) => write!(f, "Invalid disclosure proof: {msg}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for MemoError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::format;

	#[test]
	fn test_error_clone() {
		assert_eq!(
			MemoError::DecryptionFailed.clone(),
			MemoError::DecryptionFailed
		);
		assert_eq!(
			MemoError::InvalidDisclosureMask("x").clone(),
			MemoError::InvalidDisclosureMask("x")
		);
		assert_eq!(
			MemoError::InvalidProof("y").clone(),
			MemoError::InvalidProof("y")
		);
	}

	#[test]
	fn test_error_eq() {
		assert_eq!(MemoError::DataTooShort, MemoError::DataTooShort);
		assert_eq!(MemoError::DataTooLong, MemoError::DataTooLong);
		assert_eq!(MemoError::DecryptionFailed, MemoError::DecryptionFailed);
		assert_eq!(MemoError::EncryptionFailed, MemoError::EncryptionFailed);
		assert_eq!(MemoError::InvalidNoteData, MemoError::InvalidNoteData);
		assert_eq!(MemoError::CommitmentMismatch, MemoError::CommitmentMismatch);
		assert_eq!(
			MemoError::InvalidDisclosureMask("a"),
			MemoError::InvalidDisclosureMask("a")
		);
		assert_eq!(
			MemoError::InvalidDisclosureData,
			MemoError::InvalidDisclosureData
		);
		assert_eq!(MemoError::InvalidProof("b"), MemoError::InvalidProof("b"));
	}

	#[test]
	fn test_error_ne() {
		assert_ne!(MemoError::DataTooShort, MemoError::DataTooLong);
		assert_ne!(MemoError::DecryptionFailed, MemoError::EncryptionFailed);
		assert_ne!(
			MemoError::InvalidDisclosureMask("a"),
			MemoError::InvalidDisclosureMask("b")
		);
		assert_ne!(MemoError::InvalidProof("x"), MemoError::InvalidProof("y"));
	}

	#[test]
	fn test_display_data_too_short() {
		assert!(format!("{}", MemoError::DataTooShort).contains("too short"));
	}

	#[test]
	fn test_display_data_too_long() {
		let msg = format!("{}", MemoError::DataTooLong);
		assert!(msg.contains("exceeds") || msg.contains("maximum") || msg.contains("too long"));
	}

	#[test]
	fn test_display_decryption_failed() {
		let msg = format!("{}", MemoError::DecryptionFailed);
		assert!(msg.to_lowercase().contains("decryption"));
	}

	#[test]
	fn test_display_encryption_failed() {
		let msg = format!("{}", MemoError::EncryptionFailed);
		assert!(msg.to_lowercase().contains("encryption"));
	}

	#[test]
	fn test_display_invalid_note_data() {
		let msg = format!("{}", MemoError::InvalidNoteData);
		assert!(msg.to_lowercase().contains("invalid") || msg.to_lowercase().contains("note"));
	}

	#[test]
	fn test_display_commitment_mismatch() {
		let msg = format!("{}", MemoError::CommitmentMismatch);
		assert!(
			msg.to_lowercase().contains("mismatch") || msg.to_lowercase().contains("commitment")
		);
	}

	#[test]
	fn test_display_invalid_disclosure_mask_includes_message() {
		let msg = format!("{}", MemoError::InvalidDisclosureMask("no fields selected"));
		assert!(msg.contains("no fields selected"));
	}

	#[test]
	fn test_display_invalid_disclosure_data() {
		let msg = format!("{}", MemoError::InvalidDisclosureData);
		assert!(msg.to_lowercase().contains("invalid") || msg.to_lowercase().contains("disclosed"));
	}

	#[test]
	fn test_display_invalid_proof_includes_message() {
		let msg = format!("{}", MemoError::InvalidProof("empty proof bytes"));
		assert!(msg.contains("empty proof bytes"));
	}
}
