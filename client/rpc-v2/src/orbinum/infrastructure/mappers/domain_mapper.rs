//! DomainMapper - General conversions for domain types

use sp_core::H256;

use crate::orbinum::domain::{Commitment, Nullifier};

/// Generic mapper for domain types.
///
/// Centralizes conversions between pallet domain types and Substrate types.
pub struct DomainMapper;

impl DomainMapper {
	/// Converts `H256` to `Commitment`.
	pub fn h256_to_commitment(h256: H256) -> Commitment {
		Commitment::from(h256)
	}

	/// Converts `Commitment` to `H256`.
	pub fn commitment_to_h256(commitment: Commitment) -> H256 {
		H256::from_slice(commitment.as_bytes())
	}

	/// Converts `H256` to `Nullifier`.
	pub fn h256_to_nullifier(h256: H256) -> Nullifier {
		Nullifier::from(h256)
	}

	/// Converts `Nullifier` to `H256`.
	pub fn nullifier_to_h256(nullifier: Nullifier) -> H256 {
		H256::from_slice(nullifier.as_bytes())
	}

	/// Converts `H256` to hex string.
	pub fn h256_to_hex(h256: H256) -> String {
		format!("0x{}", hex::encode(h256.0))
	}

	/// Converts hex string to `H256`.
	pub fn hex_to_h256(hex_str: &str) -> Result<H256, String> {
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

		Ok(H256(arr))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_round_trip_commitment_h256() {
		let original = Commitment::new([0x11u8; 32]);
		let h256 = DomainMapper::commitment_to_h256(original);
		let decoded = DomainMapper::h256_to_commitment(h256);

		assert_eq!(decoded, original);
	}

	#[test]
	fn should_round_trip_nullifier_h256() {
		let original = Nullifier::new([0x22u8; 32]);
		let h256 = DomainMapper::nullifier_to_h256(original);
		let decoded = DomainMapper::h256_to_nullifier(h256);

		assert_eq!(decoded, original);
	}

	#[test]
	fn should_round_trip_h256_hex() {
		let original = H256([0xABu8; 32]);
		let hex = DomainMapper::h256_to_hex(original);
		let decoded = DomainMapper::hex_to_h256(&hex).expect("hex decode should succeed");

		assert_eq!(decoded, original);
	}

	#[test]
	fn should_decode_hex_without_prefix() {
		let original = H256([0xCDu8; 32]);
		let no_prefix = hex::encode(original.0);

		let decoded = DomainMapper::hex_to_h256(&no_prefix)
			.expect("hex decode without prefix should succeed");

		assert_eq!(decoded, original);
	}

	#[test]
	fn should_fail_hex_to_h256_for_invalid_length() {
		let err =
			DomainMapper::hex_to_h256("0x1234").expect_err("invalid length should return error");
		assert!(err.contains("Invalid hex length"));
	}

	#[test]
	fn should_fail_hex_to_h256_for_invalid_chars() {
		let bad = format!("0x{}", "zz".repeat(32));
		let err =
			DomainMapper::hex_to_h256(&bad).expect_err("invalid hex chars should return error");
		assert!(err.contains("Failed to decode hex"));
	}
}
