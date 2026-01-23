//! Utility functions for ZK proof handling

use crate::core::error::VerifierError;
use crate::Bn254Fr;
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
