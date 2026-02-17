//! CommitmentMapper - Conversion between domain Commitment and external types

use sp_core::H256;

use crate::orbinum::domain::Commitment;

/// Mapper for `Commitment`.
///
/// Converts between:
/// - `domain::Commitment` (reused from pallet)
/// - `sp_core::H256` (Substrate type)
/// - `String` (hex for JSON-RPC)
pub struct CommitmentMapper;

impl CommitmentMapper {
	/// Converts domain `Commitment` to Substrate `H256`.
	pub fn to_h256(commitment: Commitment) -> H256 {
		H256::from_slice(commitment.as_bytes())
	}

	/// Converts Substrate `H256` to domain `Commitment`.
	pub fn from_h256(h256: H256) -> Commitment {
		Commitment::new(h256.0)
	}

	/// Converts `Commitment` to hexadecimal string (with `0x` prefix).
	pub fn to_hex_string(commitment: Commitment) -> String {
		format!("0x{}", hex::encode(commitment.as_bytes()))
	}

	/// Converts hexadecimal string into `Commitment`.
	///
	/// # Errors
	/// - If hex format is invalid (must contain exactly 64 hex chars, optional `0x`)
	pub fn from_hex_string(hex_str: &str) -> Result<Commitment, String> {
		let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

		if hex_str.len() != 64 {
			return Err(format!(
				"Invalid hex length: expected 64, got {}",
				hex_str.len()
			));
		}

		let bytes = hex::decode(hex_str).map_err(|e| format!("Failed to decode hex: {e}"))?;

		let mut arr = [0u8; 32];
		arr.copy_from_slice(&bytes);

		Ok(Commitment::new(arr))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_round_trip_commitment_hex() {
		let original = Commitment::new([42u8; 32]);
		let hex = CommitmentMapper::to_hex_string(original);
		let decoded = CommitmentMapper::from_hex_string(&hex).expect("hex decode should succeed");
		assert_eq!(original, decoded);
	}

	#[test]
	fn should_round_trip_commitment_h256() {
		let original = Commitment::new([7u8; 32]);
		let h256 = CommitmentMapper::to_h256(original);
		let decoded = CommitmentMapper::from_h256(h256);

		assert_eq!(original, decoded);
	}

	#[test]
	fn should_decode_hex_without_prefix() {
		let original = Commitment::new([0xAAu8; 32]);
		let without_prefix = hex::encode(original.as_bytes());

		let decoded = CommitmentMapper::from_hex_string(&without_prefix)
			.expect("hex decode without prefix should succeed");

		assert_eq!(decoded, original);
	}

	#[test]
	fn should_fail_for_invalid_hex_length() {
		let err = CommitmentMapper::from_hex_string("0x1234")
			.expect_err("invalid hex length should return error");
		assert!(err.contains("Invalid hex length"));
	}

	#[test]
	fn should_fail_for_non_hex_input() {
		let bad = format!("0x{}", "zz".repeat(32));
		let err =
			CommitmentMapper::from_hex_string(&bad).expect_err("non-hex input should return error");
		assert!(err.contains("Failed to decode hex"));
	}
}
