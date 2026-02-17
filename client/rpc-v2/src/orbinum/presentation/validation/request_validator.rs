//! RequestValidator - RPC parameter validation

use jsonrpsee::core::RpcResult;
use sp_core::H256;

use crate::orbinum::presentation::validation::RpcError;

/// RPC request validator.
///
/// Centralizes input validation before data reaches services.
pub struct RequestValidator;

impl RequestValidator {
	/// Validates a leaf index.
	///
	/// # Validation
	/// - For now, any `u32` is valid
	/// - Service layer validates against current `tree_size`
	///
	/// # Future
	/// - Maximum-range validation can be added here
	pub fn validate_leaf_index(leaf_index: u32) -> RpcResult<()> {
		// Basic validation: `u32` is already type-valid
		// Service validates against current tree size
		let _ = leaf_index;
		Ok(())
	}

	/// Validates and parses a nullifier hex string.
	///
	/// # Parameters
	/// - `nullifier_hex`: Hex string (with or without `0x` prefix)
	///
	/// # Returns
	/// - `H256`: Parsed nullifier hash
	///
	/// # Validation
	/// - Must be valid hex
	/// - Must contain 64 hex chars (32 bytes)
	///
	/// # Errors
	/// - `InvalidNullifier`: If format is invalid
	pub fn validate_nullifier_hex(nullifier_hex: &str) -> RpcResult<H256> {
		// Remove `0x` prefix if present
		let hex_str = nullifier_hex.strip_prefix("0x").unwrap_or(nullifier_hex);

		// Validate length
		if hex_str.len() != 64 {
			return Err(RpcError::invalid_nullifier(format!(
				"Invalid hex length: expected 64, got {}",
				hex_str.len()
			))
			.into());
		}

		// Parse hex into bytes
		let bytes = hex::decode(hex_str)
			.map_err(|e| RpcError::invalid_nullifier(format!("Failed to decode hex: {e}")))?;

		// Convert to `H256`
		let mut arr = [0u8; 32];
		arr.copy_from_slice(&bytes);

		Ok(H256(arr))
	}

	/// Validates and parses a commitment hex string.
	///
	/// # Parameters
	/// - `commitment_hex`: Hex string (with or without `0x` prefix)
	///
	/// # Returns
	/// - `H256`: Parsed commitment hash
	///
	/// # Validation
	/// - Must be valid hex
	/// - Must contain 64 hex chars (32 bytes)
	pub fn validate_commitment_hex(commitment_hex: &str) -> RpcResult<H256> {
		// Same logic as nullifier (both are `H256`)
		Self::validate_nullifier_hex(commitment_hex)
			.map_err(|_| RpcError::invalid_commitment("Invalid commitment hex".to_string()).into())
	}

	/// Validates an asset ID.
	///
	/// # Parameters
	/// - `asset_id`: Asset identifier
	///
	/// # Validation
	/// - For now, any `u32` is valid
	/// - Pallet validates whether the asset exists
	pub fn validate_asset_id(asset_id: u32) -> RpcResult<()> {
		let _ = asset_id;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_validate_nullifier_hex_valid() {
		let hex = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
		assert!(RequestValidator::validate_nullifier_hex(hex).is_ok());
	}

	#[test]
	fn should_validate_nullifier_hex_without_prefix() {
		let hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
		assert!(RequestValidator::validate_nullifier_hex(hex).is_ok());
	}

	#[test]
	fn should_reject_nullifier_hex_invalid_length() {
		let hex = "0x1234";
		assert!(RequestValidator::validate_nullifier_hex(hex).is_err());
	}

	#[test]
	fn should_reject_nullifier_hex_invalid_chars() {
		let hex = "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
		assert!(RequestValidator::validate_nullifier_hex(hex).is_err());
	}

	#[test]
	fn should_validate_commitment_hex() {
		let hex = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		assert!(RequestValidator::validate_commitment_hex(hex).is_ok());
	}

	#[test]
	fn should_reject_commitment_hex_invalid() {
		assert!(RequestValidator::validate_commitment_hex("0x1234").is_err());
	}

	#[test]
	fn should_accept_leaf_index_and_asset_id() {
		assert!(RequestValidator::validate_leaf_index(0).is_ok());
		assert!(RequestValidator::validate_leaf_index(u32::MAX).is_ok());
		assert!(RequestValidator::validate_asset_id(0).is_ok());
		assert!(RequestValidator::validate_asset_id(u32::MAX).is_ok());
	}
}
