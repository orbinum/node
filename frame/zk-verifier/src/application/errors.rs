//! Application errors - Use case and service layer errors

use crate::domain::errors::DomainError;

/// Application layer errors
#[derive(Debug, PartialEq)]
pub enum ApplicationError {
	/// Domain layer error
	Domain(DomainError),

	/// Circuit not found in repository
	CircuitNotFound,

	/// Circuit already exists
	CircuitAlreadyExists,

	/// Repository operation failed
	RepositoryError,

	/// Validation failed
	ValidationFailed,

	/// Cryptographic operation failed
	CryptoError,
}

impl From<DomainError> for ApplicationError {
	fn from(err: DomainError) -> Self {
		Self::Domain(err)
	}
}

impl core::fmt::Display for ApplicationError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		match self {
			Self::Domain(e) => write!(f, "Domain error: {e}"),
			Self::CircuitNotFound => write!(f, "Circuit not found"),
			Self::CircuitAlreadyExists => write!(f, "Circuit already exists"),
			Self::RepositoryError => write!(f, "Repository operation failed"),
			Self::ValidationFailed => write!(f, "Validation failed"),
			Self::CryptoError => write!(f, "Cryptographic operation failed"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for ApplicationError {}
