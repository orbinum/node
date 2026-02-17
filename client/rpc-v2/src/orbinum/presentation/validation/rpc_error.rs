//! RpcError - RPC error handling

use jsonrpsee::types::{error::INTERNAL_ERROR_CODE, ErrorObjectOwned};

use crate::orbinum::application::ApplicationError;

/// Error type for the presentation layer.
#[derive(Debug, Clone)]
pub struct RpcError {
	code: i32,
	message: String,
}

impl RpcError {
	/// Creates a custom RPC error.
	pub fn new(code: i32, message: String) -> Self {
		Self { code, message }
	}

	/// Error: Invalid leaf index.
	pub fn invalid_leaf_index(index: u32, tree_size: u32) -> Self {
		Self::new(
			-32001,
			format!("Invalid leaf index {index} (tree size: {tree_size})"),
		)
	}

	/// Error: Tree not initialized.
	pub fn tree_not_initialized() -> Self {
		Self::new(-32002, "Merkle tree not initialized".to_string())
	}

	/// Error: Invalid nullifier.
	pub fn invalid_nullifier(msg: String) -> Self {
		Self::new(-32003, format!("Invalid nullifier: {msg}"))
	}

	/// Error: Invalid commitment.
	pub fn invalid_commitment(msg: String) -> Self {
		Self::new(-32004, format!("Invalid commitment: {msg}"))
	}

	/// Error: Pool not initialized.
	pub fn pool_not_initialized() -> Self {
		Self::new(-32005, "Pool not initialized".to_string())
	}

	/// Error: Storage not available.
	pub fn storage_not_available(msg: String) -> Self {
		Self::new(-32006, format!("Storage not available: {msg}"))
	}

	/// Internal error.
	pub fn internal_error(msg: String) -> Self {
		Self::new(INTERNAL_ERROR_CODE, format!("Internal error: {msg}"))
	}

	/// Converts an `ApplicationError` to `RpcError`.
	pub fn from_application_error(error: ApplicationError) -> Self {
		match error {
			ApplicationError::InvalidLeafIndex { index, tree_size } => {
				Self::invalid_leaf_index(index, tree_size)
			}
			ApplicationError::TreeNotInitialized => Self::tree_not_initialized(),
			ApplicationError::PoolNotInitialized => Self::pool_not_initialized(),
			ApplicationError::CalculationError(msg) => Self::internal_error(msg),
			ApplicationError::Domain(domain_err) => Self::from_domain_error(domain_err),
		}
	}

	/// Converts a `DomainError` to `RpcError`.
	fn from_domain_error(error: crate::orbinum::domain::DomainError) -> Self {
		match error {
			crate::orbinum::domain::DomainError::StorageNotAvailable => {
				Self::storage_not_available("Storage not available".to_string())
			}
			crate::orbinum::domain::DomainError::BlockNotFound => {
				Self::storage_not_available("Block not found".to_string())
			}
			crate::orbinum::domain::DomainError::LeafIndexOutOfBounds { index, tree_size } => {
				Self::invalid_leaf_index(index, tree_size)
			}
			crate::orbinum::domain::DomainError::MerkleTreeNotInitialized => {
				Self::tree_not_initialized()
			}
			crate::orbinum::domain::DomainError::PoolNotInitialized => Self::pool_not_initialized(),
			crate::orbinum::domain::DomainError::StorageDecodeError(msg) => {
				Self::storage_not_available(msg)
			}
			crate::orbinum::domain::DomainError::CalculationError(msg) => Self::internal_error(msg),
			crate::orbinum::domain::DomainError::NullifierNotFound => {
				Self::invalid_nullifier("Nullifier not found".to_string())
			}
		}
	}
}

impl From<RpcError> for ErrorObjectOwned {
	fn from(error: RpcError) -> Self {
		ErrorObjectOwned::owned(error.code, error.message, None::<()>)
	}
}

impl core::fmt::Display for RpcError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "RPC Error {}: {}", self.code, self.message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::DomainError;

	#[test]
	fn should_format_display_message() {
		let err = RpcError::invalid_nullifier("bad hex".to_string());
		assert_eq!(
			err.to_string(),
			"RPC Error -32003: Invalid nullifier: bad hex"
		);
	}

	#[test]
	fn should_convert_application_error_to_rpc_error() {
		let err = RpcError::from_application_error(ApplicationError::InvalidLeafIndex {
			index: 9,
			tree_size: 3,
		});
		let object: ErrorObjectOwned = err.into();

		assert_eq!(object.code(), -32001);
		assert_eq!(object.message(), "Invalid leaf index 9 (tree size: 3)");
	}

	#[test]
	fn should_convert_domain_errors_to_expected_rpc_codes() {
		let from_storage = RpcError::from_application_error(ApplicationError::Domain(
			DomainError::StorageNotAvailable,
		));
		let from_calc = RpcError::from_application_error(ApplicationError::Domain(
			DomainError::CalculationError("overflow".to_string()),
		));
		let from_nullifier = RpcError::from_application_error(ApplicationError::Domain(
			DomainError::NullifierNotFound,
		));

		let storage_obj: ErrorObjectOwned = from_storage.into();
		let calc_obj: ErrorObjectOwned = from_calc.into();
		let nullifier_obj: ErrorObjectOwned = from_nullifier.into();

		assert_eq!(storage_obj.code(), -32006);
		assert_eq!(calc_obj.code(), INTERNAL_ERROR_CODE);
		assert_eq!(nullifier_obj.code(), -32003);
	}

	#[test]
	fn should_convert_to_error_object_owned() {
		let err = RpcError::pool_not_initialized();
		let object: ErrorObjectOwned = err.into();

		assert_eq!(object.code(), -32005);
		assert_eq!(object.message(), "Pool not initialized");
	}
}
