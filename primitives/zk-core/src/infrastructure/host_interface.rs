#![allow(unexpected_cfgs)]
//! Host interface for Poseidon hash operations
//!
//! Native runtime interface exposing Poseidon hashing with ~3x performance
//! improvement over WASM by bypassing interpreter overhead.

use sp_runtime_interface::{
	pass_by::{AllocateAndReturnFatPointer, PassFatPointerAndRead},
	runtime_interface,
};

/// Native runtime interface for Poseidon hash operations
///
/// Provides native host execution bypassing WASM (~3x speedup).
#[runtime_interface]
pub trait PoseidonHostInterface {
	/// Hash two 32-byte inputs (Merkle tree, nullifier)
	fn poseidon_hash_2(
		left: PassFatPointerAndRead<&[u8]>,
		right: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		use crate::domain::ports::PoseidonHasher;
		use crate::domain::value_objects::FieldElement;
		use crate::infrastructure::crypto::LightPoseidonHasher;
		use ark_bn254::Fr;
		use ark_ff::{BigInteger, PrimeField};

		// Validate input sizes
		assert_eq!(left.len(), 32, "Left input must be 32 bytes");
		assert_eq!(right.len(), 32, "Right input must be 32 bytes");

		// Convert to fixed arrays
		let mut left_arr = [0u8; 32];
		let mut right_arr = [0u8; 32];
		left_arr.copy_from_slice(left);
		right_arr.copy_from_slice(right);

		// Convert bytes to field elements (little-endian mod order)
		let left_fr = Fr::from_le_bytes_mod_order(&left_arr);
		let right_fr = Fr::from_le_bytes_mod_order(&right_arr);

		// Hash with Poseidon (native execution, no WASM overhead)
		let hasher = LightPoseidonHasher;
		let hash_result = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);

		// Convert back to bytes (little-endian)
		let bigint = hash_result.inner().into_bigint();
		let bytes = bigint.to_bytes_le();
		bytes[..32].to_vec()
	}

	/// Hash four 32-byte inputs (note commitment)
	fn poseidon_hash_4(
		input1: PassFatPointerAndRead<&[u8]>,
		input2: PassFatPointerAndRead<&[u8]>,
		input3: PassFatPointerAndRead<&[u8]>,
		input4: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		use crate::domain::ports::PoseidonHasher;
		use crate::domain::value_objects::FieldElement;
		use crate::infrastructure::crypto::LightPoseidonHasher;
		use ark_bn254::Fr;
		use ark_ff::{BigInteger, PrimeField};

		// Validate sizes
		assert_eq!(input1.len(), 32, "Input1 must be 32 bytes");
		assert_eq!(input2.len(), 32, "Input2 must be 32 bytes");
		assert_eq!(input3.len(), 32, "Input3 must be 32 bytes");
		assert_eq!(input4.len(), 32, "Input4 must be 32 bytes");

		// Convert to fixed arrays
		let mut arr1 = [0u8; 32];
		let mut arr2 = [0u8; 32];
		let mut arr3 = [0u8; 32];
		let mut arr4 = [0u8; 32];
		arr1.copy_from_slice(input1);
		arr2.copy_from_slice(input2);
		arr3.copy_from_slice(input3);
		arr4.copy_from_slice(input4);

		// Convert all inputs to field elements
		let frs: [Fr; 4] = [
			Fr::from_le_bytes_mod_order(&arr1),
			Fr::from_le_bytes_mod_order(&arr2),
			Fr::from_le_bytes_mod_order(&arr3),
			Fr::from_le_bytes_mod_order(&arr4),
		];

		// Hash with native Poseidon (no WASM overhead)
		let hasher = LightPoseidonHasher;
		let hash_result = hasher.hash_4([
			FieldElement::new(frs[0]),
			FieldElement::new(frs[1]),
			FieldElement::new(frs[2]),
			FieldElement::new(frs[3]),
		]);

		// Convert back to bytes
		let bigint = hash_result.inner().into_bigint();
		let bytes = bigint.to_bytes_le();
		bytes[..32].to_vec()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::Fr;
	use ark_ff::{BigInteger, PrimeField, Zero};

	// Helper: Convert u64 to 32-byte array (little-endian)
	fn u64_to_bytes(value: u64) -> Vec<u8> {
		let fr = Fr::from(value);
		let bigint = fr.into_bigint();
		let bytes = bigint.to_bytes_le();
		bytes[..32].to_vec()
	}

	// Helper: Convert bytes back to Fr
	fn bytes_to_fr(bytes: &[u8]) -> Fr {
		let mut arr = [0u8; 32];
		arr.copy_from_slice(&bytes[..32]);
		Fr::from_le_bytes_mod_order(&arr)
	}

	// ===== poseidon_hash_2 Tests =====

	#[test]
	fn test_hash_2_basic() {
		let left = u64_to_bytes(42);
		let right = u64_to_bytes(100);

		let result = poseidon_host_interface::poseidon_hash_2(&left, &right);

		assert_eq!(result.len(), 32);
		let hash_fr = bytes_to_fr(&result);
		assert!(!hash_fr.is_zero());
	}

	#[test]
	fn test_hash_2_deterministic() {
		let left = u64_to_bytes(42);
		let right = u64_to_bytes(100);

		let result1 = poseidon_host_interface::poseidon_hash_2(&left, &right);
		let result2 = poseidon_host_interface::poseidon_hash_2(&left, &right);

		assert_eq!(result1, result2);
	}

	#[test]
	fn test_hash_2_zero_inputs() {
		let left = u64_to_bytes(0);
		let right = u64_to_bytes(0);

		let result = poseidon_host_interface::poseidon_hash_2(&left, &right);

		let hash_fr = bytes_to_fr(&result);
		assert!(!hash_fr.is_zero()); // Even zero inputs produce non-zero hash
	}

	#[test]
	fn test_hash_2_one_zero() {
		let left = u64_to_bytes(100);
		let right = u64_to_bytes(0);

		let result = poseidon_host_interface::poseidon_hash_2(&left, &right);

		let hash_fr = bytes_to_fr(&result);
		assert!(!hash_fr.is_zero());
	}

	#[test]
	fn test_hash_2_large_values() {
		let left = u64_to_bytes(u64::MAX);
		let right = u64_to_bytes(u64::MAX - 1);

		let result = poseidon_host_interface::poseidon_hash_2(&left, &right);

		let hash_fr = bytes_to_fr(&result);
		assert!(!hash_fr.is_zero());
	}

	#[test]
	fn test_hash_2_order_matters() {
		let left = u64_to_bytes(1);
		let right = u64_to_bytes(2);

		let hash1 = poseidon_host_interface::poseidon_hash_2(&left, &right);
		let hash2 = poseidon_host_interface::poseidon_hash_2(&right, &left);

		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_hash_2_different_inputs() {
		let hash1 = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(1), &u64_to_bytes(2));
		let hash2 = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(3), &u64_to_bytes(4));

		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_hash_2_sequential_values() {
		let hash1 =
			poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(100), &u64_to_bytes(200));
		let hash2 =
			poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(101), &u64_to_bytes(200));

		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_hash_2_multiple_calls() {
		let left = u64_to_bytes(42);
		let right = u64_to_bytes(100);

		let hashes: Vec<_> = (0..5)
			.map(|_| poseidon_host_interface::poseidon_hash_2(&left, &right))
			.collect();

		for hash in &hashes[1..] {
			assert_eq!(hash, &hashes[0]);
		}
	}

	#[test]
	#[should_panic(expected = "Left input must be 32 bytes")]
	fn test_hash_2_invalid_left_size() {
		let left = vec![0u8; 16]; // Wrong size
		let right = u64_to_bytes(100);

		poseidon_host_interface::poseidon_hash_2(&left, &right);
	}

	#[test]
	#[should_panic(expected = "Right input must be 32 bytes")]
	fn test_hash_2_invalid_right_size() {
		let left = u64_to_bytes(42);
		let right = vec![0u8; 16]; // Wrong size

		poseidon_host_interface::poseidon_hash_2(&left, &right);
	}

	// ===== poseidon_hash_4 Tests =====

	#[test]
	fn test_hash_4_basic() {
		let inputs = [
			u64_to_bytes(1),
			u64_to_bytes(2),
			u64_to_bytes(3),
			u64_to_bytes(4),
		];

		let result = poseidon_host_interface::poseidon_hash_4(
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
		);

		assert_eq!(result.len(), 32);
		let hash_fr = bytes_to_fr(&result);
		assert!(!hash_fr.is_zero());
	}

	#[test]
	fn test_hash_4_deterministic() {
		let inputs = [
			u64_to_bytes(1),
			u64_to_bytes(2),
			u64_to_bytes(3),
			u64_to_bytes(4),
		];

		let result1 = poseidon_host_interface::poseidon_hash_4(
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
		);
		let result2 = poseidon_host_interface::poseidon_hash_4(
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
		);

		assert_eq!(result1, result2);
	}

	#[test]
	fn test_hash_4_zero_inputs() {
		let inputs = [
			u64_to_bytes(0),
			u64_to_bytes(0),
			u64_to_bytes(0),
			u64_to_bytes(0),
		];

		let result = poseidon_host_interface::poseidon_hash_4(
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
		);

		let hash_fr = bytes_to_fr(&result);
		assert!(!hash_fr.is_zero());
	}

	#[test]
	fn test_hash_4_mixed_zeros() {
		let inputs = [
			u64_to_bytes(100),
			u64_to_bytes(0),
			u64_to_bytes(200),
			u64_to_bytes(0),
		];

		let result = poseidon_host_interface::poseidon_hash_4(
			&inputs[0], &inputs[1], &inputs[2], &inputs[3],
		);

		let hash_fr = bytes_to_fr(&result);
		assert!(!hash_fr.is_zero());
	}

	#[test]
	fn test_hash_4_different_inputs() {
		let inputs1 = [
			u64_to_bytes(1),
			u64_to_bytes(2),
			u64_to_bytes(3),
			u64_to_bytes(4),
		];
		let inputs2 = [
			u64_to_bytes(5),
			u64_to_bytes(6),
			u64_to_bytes(7),
			u64_to_bytes(8),
		];

		let hash1 = poseidon_host_interface::poseidon_hash_4(
			&inputs1[0],
			&inputs1[1],
			&inputs1[2],
			&inputs1[3],
		);
		let hash2 = poseidon_host_interface::poseidon_hash_4(
			&inputs2[0],
			&inputs2[1],
			&inputs2[2],
			&inputs2[3],
		);

		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_hash_4_commitment_simulation() {
		// Simulate note commitment: H(value, asset_id, owner_pubkey, blinding)
		let value = u64_to_bytes(1000);
		let asset_id = u64_to_bytes(1);
		let owner_pubkey = u64_to_bytes(12345);
		let blinding = u64_to_bytes(67890);

		let commitment =
			poseidon_host_interface::poseidon_hash_4(&value, &asset_id, &owner_pubkey, &blinding);

		let hash_fr = bytes_to_fr(&commitment);
		assert!(!hash_fr.is_zero());
	}

	#[test]
	fn test_hash_4_different_values() {
		let commitment1 = poseidon_host_interface::poseidon_hash_4(
			&u64_to_bytes(1000), // value
			&u64_to_bytes(1),    // asset_id
			&u64_to_bytes(100),  // owner
			&u64_to_bytes(200),  // blinding
		);
		let commitment2 = poseidon_host_interface::poseidon_hash_4(
			&u64_to_bytes(2000), // different value
			&u64_to_bytes(1),
			&u64_to_bytes(100),
			&u64_to_bytes(200),
		);

		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_hash_4_different_blinding() {
		let commitment1 = poseidon_host_interface::poseidon_hash_4(
			&u64_to_bytes(1000),
			&u64_to_bytes(1),
			&u64_to_bytes(100),
			&u64_to_bytes(200), // blinding
		);
		let commitment2 = poseidon_host_interface::poseidon_hash_4(
			&u64_to_bytes(1000),
			&u64_to_bytes(1),
			&u64_to_bytes(100),
			&u64_to_bytes(999), // different blinding
		);

		assert_ne!(commitment1, commitment2);
	}

	#[test]
	#[should_panic(expected = "Input1 must be 32 bytes")]
	fn test_hash_4_invalid_input1_size() {
		let invalid = vec![0u8; 16];
		let valid = u64_to_bytes(1);

		poseidon_host_interface::poseidon_hash_4(&invalid, &valid, &valid, &valid);
	}

	#[test]
	#[should_panic(expected = "Input2 must be 32 bytes")]
	fn test_hash_4_invalid_input2_size() {
		let invalid = vec![0u8; 16];
		let valid = u64_to_bytes(1);

		poseidon_host_interface::poseidon_hash_4(&valid, &invalid, &valid, &valid);
	}

	#[test]
	#[should_panic(expected = "Input3 must be 32 bytes")]
	fn test_hash_4_invalid_input3_size() {
		let invalid = vec![0u8; 16];
		let valid = u64_to_bytes(1);

		poseidon_host_interface::poseidon_hash_4(&valid, &valid, &invalid, &valid);
	}

	#[test]
	#[should_panic(expected = "Input4 must be 32 bytes")]
	fn test_hash_4_invalid_input4_size() {
		let invalid = vec![0u8; 16];
		let valid = u64_to_bytes(1);

		poseidon_host_interface::poseidon_hash_4(&valid, &valid, &valid, &invalid);
	}

	// ===== Cross-function Tests =====

	#[test]
	fn test_hash_2_vs_hash_4_different() {
		let input1 = u64_to_bytes(1);
		let input2 = u64_to_bytes(2);
		let input3 = u64_to_bytes(3);
		let input4 = u64_to_bytes(4);

		let hash2 = poseidon_host_interface::poseidon_hash_2(&input1, &input2);
		let hash4 = poseidon_host_interface::poseidon_hash_4(&input1, &input2, &input3, &input4);

		assert_ne!(hash2, hash4);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_merkle_nullifier_workflow() {
		// Simulate Merkle tree computation
		let leaf1 = u64_to_bytes(100);
		let leaf2 = u64_to_bytes(200);
		let parent = poseidon_host_interface::poseidon_hash_2(&leaf1, &leaf2);

		// Simulate nullifier computation
		let commitment = u64_to_bytes(12345);
		let spending_key = u64_to_bytes(67890);
		let nullifier = poseidon_host_interface::poseidon_hash_2(&commitment, &spending_key);

		assert_ne!(parent, nullifier);
		assert!(!bytes_to_fr(&parent).is_zero());
		assert!(!bytes_to_fr(&nullifier).is_zero());
	}

	#[test]
	fn test_commitment_and_nullifier() {
		// Create commitment
		let commitment = poseidon_host_interface::poseidon_hash_4(
			&u64_to_bytes(1000), // value
			&u64_to_bytes(1),    // asset_id
			&u64_to_bytes(100),  // owner
			&u64_to_bytes(200),  // blinding
		);

		// Create nullifier from commitment
		let spending_key = u64_to_bytes(999);
		let nullifier = poseidon_host_interface::poseidon_hash_2(&commitment, &spending_key);

		assert_ne!(commitment, nullifier);
		assert!(!bytes_to_fr(&commitment).is_zero());
		assert!(!bytes_to_fr(&nullifier).is_zero());
	}

	// ===== Byte Conversion Tests =====

	#[test]
	fn test_byte_roundtrip() {
		let original = Fr::from(42u64);
		let bytes = {
			let bigint = original.into_bigint();
			let b = bigint.to_bytes_le();
			b[..32].to_vec()
		};
		let recovered = bytes_to_fr(&bytes);

		assert_eq!(original, recovered);
	}

	#[test]
	fn test_u64_to_bytes_length() {
		let bytes = u64_to_bytes(12345);
		assert_eq!(bytes.len(), 32);
	}
}
