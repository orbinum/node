//! Utility functions for ZK proof handling

use crate::{domain::value_objects::errors::VerifierError, Bn254Fr};
use ark_ff::{BigInteger, PrimeField};

/// Convert a field element to bytes (big-endian)
pub fn field_to_bytes(field: &Bn254Fr) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	let elem_bytes = field.into_bigint().to_bytes_be();
	let start = 32 - elem_bytes.len();
	bytes[start..].copy_from_slice(&elem_bytes);
	bytes
}

/// Convert bytes (big-endian) to a field element
pub fn bytes_to_field(bytes: &[u8; 32]) -> Result<Bn254Fr, VerifierError> {
	Ok(Bn254Fr::from_be_bytes_mod_order(bytes))
}

/// Hash two field elements together (simple addition for now)
///
/// In production, this should use Poseidon or another ZK-friendly hash
pub fn hash_two_fields(left: &Bn254Fr, right: &Bn254Fr) -> Bn254Fr {
	*left + *right
}

/// Convert a u64 to a field element
pub fn u64_to_field(value: u64) -> Bn254Fr {
	Bn254Fr::from(value)
}

/// Convert a field element to u64 (if it fits)
pub fn field_to_u64(field: &Bn254Fr) -> Option<u64> {
	// Check if the field element is small enough to fit in u64
	let bigint = field.into_bigint();
	let bytes = bigint.to_bytes_le();

	// Check if only the first 8 bytes are non-zero
	if bytes.iter().skip(8).any(|&b| b != 0) {
		return None;
	}

	// Convert first 8 bytes to u64
	let mut result = 0u64;
	for (i, &byte) in bytes.iter().take(8).enumerate() {
		result |= (byte as u64) << (i * 8);
	}

	Some(result)
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_ff::PrimeField;

	// field_to_bytes tests
	#[test]
	fn test_field_to_bytes_zero() {
		let field = Bn254Fr::from(0u64);
		let bytes = field_to_bytes(&field);
		assert_eq!(bytes, [0u8; 32]);
	}

	#[test]
	fn test_field_to_bytes_one() {
		let field = Bn254Fr::from(1u64);
		let bytes = field_to_bytes(&field);
		// Should be 1 in big-endian (last byte is 1)
		let mut expected = [0u8; 32];
		expected[31] = 1;
		assert_eq!(bytes, expected);
	}

	#[test]
	fn test_field_to_bytes_max_u64() {
		let field = Bn254Fr::from(u64::MAX);
		let bytes = field_to_bytes(&field);
		// Last 8 bytes should be 0xFF
		assert_eq!(&bytes[24..], &[0xFF; 8]);
		// First 24 bytes should be 0
		assert_eq!(&bytes[..24], &[0u8; 24]);
	}

	#[test]
	fn test_field_to_bytes_large_value() {
		let field = Bn254Fr::from(123456789u64);
		let bytes = field_to_bytes(&field);
		// Should be able to convert back
		let recovered = bytes_to_field(&bytes).unwrap();
		assert_eq!(field, recovered);
	}

	// bytes_to_field tests
	#[test]
	fn test_bytes_to_field_zero() {
		let bytes = [0u8; 32];
		let field = bytes_to_field(&bytes).unwrap();
		assert_eq!(field, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_bytes_to_field_one() {
		let mut bytes = [0u8; 32];
		bytes[31] = 1;
		let field = bytes_to_field(&bytes).unwrap();
		assert_eq!(field, Bn254Fr::from(1u64));
	}

	#[test]
	fn test_bytes_to_field_max_u64() {
		let mut bytes = [0u8; 32];
		bytes[24..].copy_from_slice(&[0xFF; 8]);
		let field = bytes_to_field(&bytes).unwrap();
		assert_eq!(field, Bn254Fr::from(u64::MAX));
	}

	#[test]
	fn test_bytes_to_field_roundtrip() {
		let original = Bn254Fr::from(987654321u64);
		let bytes = field_to_bytes(&original);
		let recovered = bytes_to_field(&bytes).unwrap();
		assert_eq!(original, recovered);
	}

	// hash_two_fields tests
	#[test]
	fn test_hash_two_fields_zeros() {
		let left = Bn254Fr::from(0u64);
		let right = Bn254Fr::from(0u64);
		let result = hash_two_fields(&left, &right);
		assert_eq!(result, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_hash_two_fields_commutative() {
		let left = Bn254Fr::from(42u64);
		let right = Bn254Fr::from(100u64);
		let result1 = hash_two_fields(&left, &right);
		let result2 = hash_two_fields(&right, &left);
		// Addition is commutative
		assert_eq!(result1, result2);
	}

	#[test]
	fn test_hash_two_fields_simple_addition() {
		let left = Bn254Fr::from(10u64);
		let right = Bn254Fr::from(20u64);
		let result = hash_two_fields(&left, &right);
		assert_eq!(result, Bn254Fr::from(30u64));
	}

	#[test]
	fn test_hash_two_fields_large_values() {
		let left = Bn254Fr::from(u64::MAX);
		let right = Bn254Fr::from(1u64);
		let result = hash_two_fields(&left, &right);
		// Should not panic, modular arithmetic handles overflow
		assert_ne!(result, left);
		assert_ne!(result, right);
	}

	// u64_to_field tests
	#[test]
	fn test_u64_to_field_zero() {
		let field = u64_to_field(0);
		assert_eq!(field, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_u64_to_field_one() {
		let field = u64_to_field(1);
		assert_eq!(field, Bn254Fr::from(1u64));
	}

	#[test]
	fn test_u64_to_field_max_u64() {
		let field = u64_to_field(u64::MAX);
		assert_eq!(field, Bn254Fr::from(u64::MAX));
	}

	#[test]
	fn test_u64_to_field_large_value() {
		let value = 123456789012345u64;
		let field = u64_to_field(value);
		assert_eq!(field, Bn254Fr::from(value));
	}

	// field_to_u64 tests
	#[test]
	fn test_field_to_u64_zero() {
		let field = Bn254Fr::from(0u64);
		let result = field_to_u64(&field);
		assert_eq!(result, Some(0));
	}

	#[test]
	fn test_field_to_u64_one() {
		let field = Bn254Fr::from(1u64);
		let result = field_to_u64(&field);
		assert_eq!(result, Some(1));
	}

	#[test]
	fn test_field_to_u64_max_u64() {
		let field = Bn254Fr::from(u64::MAX);
		let result = field_to_u64(&field);
		assert_eq!(result, Some(u64::MAX));
	}

	#[test]
	fn test_field_to_u64_large_value() {
		let value = 987654321u64;
		let field = Bn254Fr::from(value);
		let result = field_to_u64(&field);
		assert_eq!(result, Some(value));
	}

	#[test]
	fn test_field_to_u64_too_large() {
		// Create a field element larger than u64::MAX
		// Use from_be_bytes_mod_order with a large value
		let mut bytes = [0u8; 32];
		bytes[0] = 1; // Set a high-order bit
		let field = Bn254Fr::from_be_bytes_mod_order(&bytes);
		let result = field_to_u64(&field);
		// Should return None because it doesn't fit in u64
		assert!(result.is_none());
	}

	// Roundtrip tests
	#[test]
	fn test_u64_field_roundtrip_small() {
		let original = 42u64;
		let field = u64_to_field(original);
		let recovered = field_to_u64(&field);
		assert_eq!(recovered, Some(original));
	}

	#[test]
	fn test_u64_field_roundtrip_large() {
		let original = u64::MAX;
		let field = u64_to_field(original);
		let recovered = field_to_u64(&field);
		assert_eq!(recovered, Some(original));
	}

	#[test]
	fn test_bytes_field_roundtrip_multiple_values() {
		let values = [0u64, 1, 42, 1000, u64::MAX / 2, u64::MAX];
		for value in values {
			let field = Bn254Fr::from(value);
			let bytes = field_to_bytes(&field);
			let recovered = bytes_to_field(&bytes).unwrap();
			assert_eq!(field, recovered, "Failed for value {value}");
		}
	}
}
