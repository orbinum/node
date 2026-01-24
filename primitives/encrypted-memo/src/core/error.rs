//! Error types for encrypted memo operations

/// Errors that can occur during encryption/decryption
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
}
