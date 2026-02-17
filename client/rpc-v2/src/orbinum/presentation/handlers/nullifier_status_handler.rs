//! NullifierStatusHandler - Handler to verify nullifier status

use std::sync::Arc;

use jsonrpsee::core::RpcResult;

use crate::orbinum::{
	application::{NullifierService, NullifierStatusResponse},
	infrastructure::mappers::DomainMapper,
	presentation::validation::{RequestValidator, RpcError},
};

/// Handler for `privacy_getNullifierStatus`.
pub struct NullifierStatusHandler<Q> {
	nullifier_service: Arc<NullifierService<Q>>,
}

impl<Q> NullifierStatusHandler<Q>
where
	Q: crate::orbinum::domain::BlockchainQuery + crate::orbinum::domain::NullifierQuery,
{
	/// Creates a new `NullifierStatusHandler`.
	pub fn new(nullifier_service: Arc<NullifierService<Q>>) -> Self {
		Self { nullifier_service }
	}

	/// Handles request to verify a nullifier.
	///
	/// # Parameters
	/// - `nullifier_hex`: Nullifier hash hex string (with or without `0x`)
	///
	/// # Returns
	/// - `NullifierStatusResponse`: DTO with nullifier and `is_spent`
	///
	/// # Errors
	/// - `InvalidNullifier`: If hex string is invalid
	pub fn handle(&self, nullifier_hex: String) -> RpcResult<NullifierStatusResponse> {
		// 1. Validate and parse input
		let nullifier_h256 = RequestValidator::validate_nullifier_hex(&nullifier_hex)?;
		let nullifier = DomainMapper::h256_to_nullifier(nullifier_h256);

		// 2. Query status from service
		let is_spent = self
			.nullifier_service
			.is_spent(nullifier)
			.map_err(RpcError::from_application_error)?;

		// 3. Build response DTO
		let response = NullifierStatusResponse::new(nullifier_hex, is_spent);

		Ok(response)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::{
		BlockHash, BlockchainQuery, DomainResult, Nullifier, NullifierQuery,
	};

	#[derive(Clone, Copy)]
	struct MockQuery;

	impl BlockchainQuery for MockQuery {
		fn best_hash(&self) -> DomainResult<BlockHash> {
			Ok(BlockHash::new([4u8; 32]))
		}

		fn storage_at(
			&self,
			_block_hash: BlockHash,
			_storage_key: &[u8],
		) -> DomainResult<Option<Vec<u8>>> {
			Ok(None)
		}
	}

	impl NullifierQuery for MockQuery {
		fn is_nullifier_spent(
			&self,
			_block_hash: BlockHash,
			nullifier: Nullifier,
		) -> DomainResult<bool> {
			Ok(nullifier.as_bytes()[0] == 0xFF)
		}
	}

	#[test]
	fn should_return_nullifier_status_response() {
		let service = Arc::new(NullifierService::new(MockQuery));
		let handler = NullifierStatusHandler::new(service);
		let nullifier_hex = format!("0x{}", "ff".repeat(32));

		let response = handler
			.handle(nullifier_hex.clone())
			.expect("handler should succeed");

		assert_eq!(response.nullifier, nullifier_hex);
		assert!(response.is_spent);
	}

	#[test]
	fn should_fail_for_invalid_nullifier_hex() {
		let service = Arc::new(NullifierService::new(MockQuery));
		let handler = NullifierStatusHandler::new(service);

		let result = handler.handle("0x1234".to_string());

		assert!(result.is_err());
	}
}
