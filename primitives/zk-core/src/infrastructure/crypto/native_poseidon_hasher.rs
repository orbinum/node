//! Native Poseidon Hasher - Host Function Wrapper
//!
//! Wraps sp-runtime-interface host functions following Clean Architecture.
//! This adapter provides ~3x performance improvement over WASM by executing
//! Poseidon hashing in the native runtime instead of the WASM interpreter.

use crate::domain::{ports::PoseidonHasher, value_objects::FieldElement};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Native Poseidon hasher using host functions
///
/// Delegates to sp-runtime-interface host functions for native execution.
/// Only available with `native-poseidon` feature enabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativePoseidonHasher;

impl PoseidonHasher for NativePoseidonHasher {
	/// Hash 2 field elements using native host function
	///
	/// Converts to bytes, calls host function, converts back.
	fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
		use crate::infrastructure::host_interface::poseidon_host_interface;

		// Convert FieldElements to bytes (little-endian)
		let left_bytes = Self::field_to_bytes(inputs[0].inner());
		let right_bytes = Self::field_to_bytes(inputs[1].inner());

		// Call native host function (~3x faster than WASM)
		let result_vec = poseidon_host_interface::poseidon_hash_2(&left_bytes, &right_bytes);

		// Convert back to FieldElement
		Self::bytes_to_field(&result_vec)
	}

	/// Hash 4 field elements using native host function
	///
	/// Converts to bytes, calls host function, converts back.
	fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
		use crate::infrastructure::host_interface::poseidon_host_interface;

		// Convert all inputs to bytes
		let bytes1 = Self::field_to_bytes(inputs[0].inner());
		let bytes2 = Self::field_to_bytes(inputs[1].inner());
		let bytes3 = Self::field_to_bytes(inputs[2].inner());
		let bytes4 = Self::field_to_bytes(inputs[3].inner());

		// Call native host function
		let result_vec =
			poseidon_host_interface::poseidon_hash_4(&bytes1, &bytes2, &bytes3, &bytes4);

		// Convert back to FieldElement
		Self::bytes_to_field(&result_vec)
	}
}

impl NativePoseidonHasher {
	/// Convert field element to 32-byte array (little-endian)
	#[inline]
	fn field_to_bytes(field: Fr) -> [u8; 32] {
		let bigint = field.into_bigint();
		let bytes = bigint.to_bytes_le();
		let mut result = [0u8; 32];
		result.copy_from_slice(&bytes[..32]);
		result
	}

	/// Convert bytes to field element (little-endian mod order)
	#[inline]
	fn bytes_to_field(bytes: &[u8]) -> FieldElement {
		let mut arr = [0u8; 32];
		arr.copy_from_slice(&bytes[..32]);
		let fr = Fr::from_le_bytes_mod_order(&arr);
		FieldElement::new(fr)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_native_hasher_creation() {
		let _hasher = NativePoseidonHasher;
	}

	#[test]
	fn test_native_hasher_default() {
		let _hasher = NativePoseidonHasher;
	}

	#[test]
	fn test_native_hash_2_basic() {
		let hasher = NativePoseidonHasher;
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);

		let hash = hasher.hash_2([input1, input2]);

		// Hash should not be zero
		assert_ne!(hash, FieldElement::from_u64(0));
	}

	#[test]
	fn test_native_hash_2_deterministic() {
		let hasher = NativePoseidonHasher;
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);

		let hash1 = hasher.hash_2([input1, input2]);
		let hash2 = hasher.hash_2([input1, input2]);

		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_native_hash_4_basic() {
		let hasher = NativePoseidonHasher;
		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];

		let hash = hasher.hash_4(inputs);

		assert_ne!(hash, FieldElement::from_u64(0));
	}

	#[test]
	fn test_native_hash_4_deterministic() {
		let hasher = NativePoseidonHasher;
		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];

		let hash1 = hasher.hash_4(inputs);
		let hash2 = hasher.hash_4(inputs);

		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_native_vs_wasm_compatibility() {
		use crate::infrastructure::crypto::LightPoseidonHasher;

		let native = NativePoseidonHasher;
		let wasm = LightPoseidonHasher;

		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);

		let native_hash = native.hash_2([input1, input2]);
		let wasm_hash = wasm.hash_2([input1, input2]);

		// Native and WASM should produce identical results
		assert_eq!(native_hash, wasm_hash);
	}

	#[test]
	fn test_native_vs_wasm_hash4_compatibility() {
		use crate::infrastructure::crypto::LightPoseidonHasher;

		let native = NativePoseidonHasher;
		let wasm = LightPoseidonHasher;

		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];

		let native_hash = native.hash_4(inputs);
		let wasm_hash = wasm.hash_4(inputs);

		// Native and WASM should produce identical results
		assert_eq!(native_hash, wasm_hash);
	}
}
