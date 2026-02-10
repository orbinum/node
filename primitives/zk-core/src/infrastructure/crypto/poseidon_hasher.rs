//! Light Poseidon Hasher - Infrastructure Adapter
//!
//! Concrete implementation of `PoseidonHasher` using `light-poseidon` library.

use crate::domain::{ports::PoseidonHasher, value_objects::FieldElement};
use ark_bn254::Fr;
use light_poseidon_nostd::{Poseidon, PoseidonHasher as LightHasher};

/// Light Poseidon hasher adapter
///
/// Zero-sized type implementing domain `PoseidonHasher` port.
#[derive(Debug, Clone, Copy, Default)]
pub struct LightPoseidonHasher;

impl PoseidonHasher for LightPoseidonHasher {
	/// Hash 2 field elements using Poseidon
	///
	/// Used for Merkle tree and nullifier computation.
	fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
		// Convert FieldElement wrappers to Fr
		let fr_inputs = [inputs[0].inner(), inputs[1].inner()];

		// Use light-poseidon hash
		let result = Poseidon::<Fr>::new_circom(2)
			.expect("Failed to initialize Poseidon with 2 inputs")
			.hash(&fr_inputs)
			.expect("Poseidon hash failed");

		FieldElement::new(result)
	}

	/// Hash 4 field elements using Poseidon
	///
	/// Used for note commitment computation.
	fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
		// Convert FieldElement wrappers to Fr
		let fr_inputs = [
			inputs[0].inner(),
			inputs[1].inner(),
			inputs[2].inner(),
			inputs[3].inner(),
		];

		// Use light-poseidon hash
		let result = Poseidon::<Fr>::new_circom(4)
			.expect("Failed to initialize Poseidon with 4 inputs")
			.hash(&fr_inputs)
			.expect("Poseidon hash failed");

		FieldElement::new(result)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::{format, vec::Vec};

	// ===== Construction Tests =====

	#[test]
	fn test_new_default() {
		let _hasher = LightPoseidonHasher;
	}

	#[test]
	fn test_default_trait() {
		let _hasher = LightPoseidonHasher;
	}

	#[test]
	fn test_clone() {
		let hasher1 = LightPoseidonHasher;
		let hasher2 = hasher1;
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);
		let hash1 = hasher1.hash_2([input1, input2]);
		let hash2 = hasher2.hash_2([input1, input2]);
		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_copy() {
		let hasher1 = LightPoseidonHasher;
		let hasher2 = hasher1; // Copy
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);
		let hash1 = hasher1.hash_2([input1, input2]);
		let hash2 = hasher2.hash_2([input1, input2]);
		assert_eq!(hash1, hash2);
	}

	// ===== Hash 2 Basic Tests =====

	#[test]
	fn test_hash_2() {
		let hasher = LightPoseidonHasher;
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);
		let hash = hasher.hash_2([input1, input2]);
		assert!(!hash.is_zero());
	}

	#[test]
	fn test_hash_2_zero_inputs() {
		let hasher = LightPoseidonHasher;
		let input1 = FieldElement::from_u64(0);
		let input2 = FieldElement::from_u64(0);
		let hash = hasher.hash_2([input1, input2]);
		// Even zero inputs produce non-zero hash
		assert!(!hash.is_zero());
	}

	#[test]
	fn test_hash_2_one_zero() {
		let hasher = LightPoseidonHasher;
		let input1 = FieldElement::from_u64(100);
		let input2 = FieldElement::from_u64(0);
		let hash = hasher.hash_2([input1, input2]);
		assert!(!hash.is_zero());
	}

	#[test]
	fn test_hash_2_large_values() {
		let hasher = LightPoseidonHasher;
		let input1 = FieldElement::from_u64(u64::MAX);
		let input2 = FieldElement::from_u64(u64::MAX - 1);
		let hash = hasher.hash_2([input1, input2]);
		assert!(!hash.is_zero());
	}

	// ===== Hash 2 Determinism Tests =====

	#[test]
	fn test_hash_2_deterministic() {
		let hasher = LightPoseidonHasher;
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);
		let hash1 = hasher.hash_2([input1, input2]);
		let hash2 = hasher.hash_2([input1, input2]);
		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_hash_2_multiple_calls() {
		let hasher = LightPoseidonHasher;
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);
		let hashes: Vec<_> = (0..5).map(|_| hasher.hash_2([input1, input2])).collect();
		for hash in &hashes[1..] {
			assert_eq!(hash, &hashes[0]);
		}
	}

	// ===== Hash 2 Order Tests =====

	#[test]
	fn test_hash_2_order_matters() {
		let hasher = LightPoseidonHasher;
		let hash1 = hasher.hash_2([FieldElement::from_u64(1), FieldElement::from_u64(2)]);
		let hash2 = hasher.hash_2([FieldElement::from_u64(2), FieldElement::from_u64(1)]);
		assert_ne!(hash1, hash2);
	}

	// ===== Hash 2 Collision Tests =====

	#[test]
	fn test_hash_2_different_inputs() {
		let hasher = LightPoseidonHasher;
		let hash1 = hasher.hash_2([FieldElement::from_u64(1), FieldElement::from_u64(2)]);
		let hash2 = hasher.hash_2([FieldElement::from_u64(3), FieldElement::from_u64(4)]);
		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_hash_2_sequential_values() {
		let hasher = LightPoseidonHasher;
		let hash1 = hasher.hash_2([FieldElement::from_u64(100), FieldElement::from_u64(200)]);
		let hash2 = hasher.hash_2([FieldElement::from_u64(101), FieldElement::from_u64(200)]);
		assert_ne!(hash1, hash2);
	}

	// ===== Hash 4 Basic Tests =====

	#[test]
	fn test_hash_4() {
		let hasher = LightPoseidonHasher;
		let inputs = [
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		];
		let hash = hasher.hash_4(inputs);
		assert!(!hash.is_zero());
	}

	#[test]
	fn test_hash_4_zero_inputs() {
		let hasher = LightPoseidonHasher;
		let inputs = [
			FieldElement::from_u64(0),
			FieldElement::from_u64(0),
			FieldElement::from_u64(0),
			FieldElement::from_u64(0),
		];
		let hash = hasher.hash_4(inputs);
		assert!(!hash.is_zero());
	}

	#[test]
	fn test_hash_4_mixed_zeros() {
		let hasher = LightPoseidonHasher;
		let inputs = [
			FieldElement::from_u64(100),
			FieldElement::from_u64(0),
			FieldElement::from_u64(200),
			FieldElement::from_u64(0),
		];
		let hash = hasher.hash_4(inputs);
		assert!(!hash.is_zero());
	}

	// ===== Hash 4 Determinism Tests =====

	#[test]
	fn test_hash_4_deterministic() {
		let hasher = LightPoseidonHasher;
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

	// ===== Hash 4 Collision Tests =====

	#[test]
	fn test_hash_4_different_inputs() {
		let hasher = LightPoseidonHasher;
		let hash1 = hasher.hash_4([
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		]);
		let hash2 = hasher.hash_4([
			FieldElement::from_u64(5),
			FieldElement::from_u64(6),
			FieldElement::from_u64(7),
			FieldElement::from_u64(8),
		]);
		assert_ne!(hash1, hash2);
	}

	// ===== Domain Use Case Tests =====

	#[test]
	fn test_commitment_computation() {
		let hasher = LightPoseidonHasher;
		// H(value, asset_id, owner_pubkey, blinding)
		let value = FieldElement::from_u64(1000);
		let asset_id = FieldElement::from_u64(1);
		let owner_pubkey = FieldElement::from_u64(12345);
		let blinding = FieldElement::from_u64(67890);
		let commitment = hasher.hash_4([value, asset_id, owner_pubkey, blinding]);
		assert!(!commitment.is_zero());
	}

	#[test]
	fn test_nullifier_computation() {
		let hasher = LightPoseidonHasher;
		// H(commitment, spending_key)
		let commitment = FieldElement::from_u64(111111);
		let spending_key = FieldElement::from_u64(222222);
		let nullifier = hasher.hash_2([commitment, spending_key]);
		assert!(!nullifier.is_zero());
	}

	#[test]
	fn test_merkle_parent_computation() {
		let hasher = LightPoseidonHasher;
		// H(left_child, right_child)
		let left = FieldElement::from_u64(11111);
		let right = FieldElement::from_u64(22222);
		let parent = hasher.hash_2([left, right]);
		assert!(!parent.is_zero());
	}

	#[test]
	fn test_commitment_different_values() {
		let hasher = LightPoseidonHasher;
		let commitment1 = hasher.hash_4([
			FieldElement::from_u64(1000), // value
			FieldElement::from_u64(1),    // asset_id
			FieldElement::from_u64(100),  // owner
			FieldElement::from_u64(200),  // blinding
		]);
		let commitment2 = hasher.hash_4([
			FieldElement::from_u64(2000), // different value
			FieldElement::from_u64(1),
			FieldElement::from_u64(100),
			FieldElement::from_u64(200),
		]);
		assert_ne!(commitment1, commitment2);
	}

	#[test]
	fn test_commitment_different_blinding() {
		let hasher = LightPoseidonHasher;
		let commitment1 = hasher.hash_4([
			FieldElement::from_u64(1000),
			FieldElement::from_u64(1),
			FieldElement::from_u64(100),
			FieldElement::from_u64(200), // blinding
		]);
		let commitment2 = hasher.hash_4([
			FieldElement::from_u64(1000),
			FieldElement::from_u64(1),
			FieldElement::from_u64(100),
			FieldElement::from_u64(999), // different blinding
		]);
		assert_ne!(commitment1, commitment2);
	}

	// ===== Merkle Tree Tests =====

	#[test]
	fn test_merkle_tree_levels() {
		let hasher = LightPoseidonHasher;
		// Simulate 3 levels of Merkle tree
		let leaf1 = FieldElement::from_u64(1);
		let leaf2 = FieldElement::from_u64(2);
		let leaf3 = FieldElement::from_u64(3);
		let leaf4 = FieldElement::from_u64(4);
		// Level 1
		let parent1 = hasher.hash_2([leaf1, leaf2]);
		let parent2 = hasher.hash_2([leaf3, leaf4]);
		// Level 2 (root)
		let root = hasher.hash_2([parent1, parent2]);
		assert!(!root.is_zero());
	}

	// ===== Trait Implementation Tests =====

	#[test]
	fn test_poseidon_hasher_trait() {
		let hasher: &dyn PoseidonHasher = &LightPoseidonHasher;
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);
		let hash = hasher.hash_2([input1, input2]);
		assert!(!hash.is_zero());
	}

	#[test]
	fn test_multiple_hashers_same_result() {
		let hasher1 = LightPoseidonHasher;
		let hasher2 = LightPoseidonHasher;
		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);
		let hash1 = hasher1.hash_2([input1, input2]);
		let hash2 = hasher2.hash_2([input1, input2]);
		assert_eq!(hash1, hash2);
	}

	// ===== Debug Tests =====

	#[test]
	fn test_debug_format() {
		let hasher = LightPoseidonHasher;
		let debug_str = format!("{hasher:?}");
		assert!(debug_str.contains("LightPoseidonHasher"));
	}
}
