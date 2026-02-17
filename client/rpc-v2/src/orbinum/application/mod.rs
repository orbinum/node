//! Application layer - Use cases and application services
//!
//! This layer orchestrates operations between domain and infrastructure.
//! - Services coordinate business logic through domain ports
//! - DTOs map domain entities to the presentation layer
//! - No direct FRAME dependencies (ports only)

pub mod dto;
pub mod services;

// Service re-exports
pub use services::{MerkleProofService, NullifierService, PoolQueryService};

// DTO re-exports
pub use dto::{MerkleProofResponse, NullifierStatusResponse, PoolStatsResponse};

/// Application layer error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationError {
	/// Domain-layer error.
	Domain(crate::orbinum::domain::DomainError),
	/// Invalid leaf index.
	InvalidLeafIndex { index: u32, tree_size: u32 },
	/// Merkle tree is not initialized.
	TreeNotInitialized,
	/// Pool is not initialized.
	PoolNotInitialized,
	/// Calculation error.
	CalculationError(String),
}

impl From<crate::orbinum::domain::DomainError> for ApplicationError {
	fn from(error: crate::orbinum::domain::DomainError) -> Self {
		Self::Domain(error)
	}
}

impl core::fmt::Display for ApplicationError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Domain(e) => write!(f, "Domain error: {e}"),
			Self::InvalidLeafIndex { index, tree_size } => {
				write!(f, "Invalid leaf index {index} (tree size: {tree_size})")
			}
			Self::TreeNotInitialized => write!(f, "Merkle tree not initialized"),
			Self::PoolNotInitialized => write!(f, "Pool not initialized"),
			Self::CalculationError(msg) => write!(f, "Calculation error: {msg}"),
		}
	}
}

/// Application layer result type.
pub type ApplicationResult<T> = Result<T, ApplicationError>;

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::DomainError;

	#[test]
	fn should_convert_domain_error_into_application_error() {
		let domain_error = DomainError::BlockNotFound;
		let app_error: ApplicationError = domain_error.clone().into();

		assert_eq!(app_error, ApplicationError::Domain(domain_error));
	}

	#[test]
	fn should_render_display_messages_for_all_variants() {
		let domain = ApplicationError::Domain(DomainError::StorageNotAvailable).to_string();
		let invalid = ApplicationError::InvalidLeafIndex {
			index: 3,
			tree_size: 2,
		}
		.to_string();
		let tree = ApplicationError::TreeNotInitialized.to_string();
		let pool = ApplicationError::PoolNotInitialized.to_string();
		let calc = ApplicationError::CalculationError("overflow".to_string()).to_string();

		assert_eq!(domain, "Domain error: Storage not available");
		assert_eq!(invalid, "Invalid leaf index 3 (tree size: 2)");
		assert_eq!(tree, "Merkle tree not initialized");
		assert_eq!(pool, "Pool not initialized");
		assert_eq!(calc, "Calculation error: overflow");
	}

	#[test]
	fn should_support_application_result_alias() {
		let ok_value: ApplicationResult<u32> = Ok(42);
		let err_value: ApplicationResult<u32> = Err(ApplicationError::PoolNotInitialized);

		assert_eq!(ok_value, Ok(42));
		assert!(matches!(
			err_value,
			Err(ApplicationError::PoolNotInitialized)
		));
	}
}
