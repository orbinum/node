//! Light Poseidon Hasher - Infrastructure Adapter
//!
//! Concrete implementation of the `PoseidonHasher` port using the
//! `light-poseidon` library. This adapter bridges domain logic with
//! the external cryptographic library.
//!

//! - **Domain Port**: `domain::ports::PoseidonHasher` trait
//! - **Adapter**: `LightPoseidonHasher` struct (this file)
//! - **External Lib**: `light_poseidon` crate
//!

//! ```rust
//! use orbinum_zk_core::domain::ports::PoseidonHasher;
//! use orbinum_zk_core::infrastructure::crypto::LightPoseidonHasher;
//! use orbinum_zk_core::domain::value_objects::FieldElement;
//! use ark_bn254::Fr;
//!
//! let hasher = LightPoseidonHasher;
//! let field1 = FieldElement::new(Fr::from(1u64));
//! let field2 = FieldElement::new(Fr::from(2u64));
//! let hash = hasher.hash_2([field1, field2]);
//! ```

use crate::domain::{ports::PoseidonHasher, value_objects::FieldElement};
use ark_bn254::Fr;
use light_poseidon_nostd::{Poseidon, PoseidonHasher as LightHasher};

/// Light Poseidon hasher adapter.
///
/// Implements the domain `PoseidonHasher` port using `light-poseidon`.
/// This is a zero-sized type (ZST) as the library uses stateless functions.
#[derive(Debug, Clone, Copy, Default)]
pub struct LightPoseidonHasher;

impl PoseidonHasher for LightPoseidonHasher {
	/// Hash 2 field elements using Poseidon.
	///
	/// Used for:
	/// - Merkle tree parent computation
	/// - Nullifier generation: `H(commitment, spending_key)`
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

	/// Hash 4 field elements using Poseidon.
	///
	/// Used for:
	/// - Note commitment: `H(value, asset_id, owner_pubkey, blinding)`
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

	#[test]
	fn test_light_poseidon_hash_2() {
		let hasher = LightPoseidonHasher;

		let input1 = FieldElement::from_u64(42);
		let input2 = FieldElement::from_u64(100);

		let hash = hasher.hash_2([input1, input2]);

		// Hash should not be zero
		assert!(!hash.is_zero());

		// Same inputs produce same hash (determinism)
		let hash2 = hasher.hash_2([input1, input2]);
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_light_poseidon_hash_4() {
		let hasher = LightPoseidonHasher;

		let input1 = FieldElement::from_u64(1);
		let input2 = FieldElement::from_u64(2);
		let input3 = FieldElement::from_u64(3);
		let input4 = FieldElement::from_u64(4);

		let hash = hasher.hash_4([input1, input2, input3, input4]);

		// Hash should not be zero
		assert!(!hash.is_zero());

		// Same inputs produce same hash
		let hash2 = hasher.hash_4([input1, input2, input3, input4]);
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_different_inputs_different_hashes() {
		let hasher = LightPoseidonHasher;

		let hash1 = hasher.hash_2([FieldElement::from_u64(1), FieldElement::from_u64(2)]);
		let hash2 = hasher.hash_2([FieldElement::from_u64(3), FieldElement::from_u64(4)]);

		// Different inputs should produce different hashes
		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_poseidon_order_matters() {
		let hasher = LightPoseidonHasher;

		let hash1 = hasher.hash_2([FieldElement::from_u64(1), FieldElement::from_u64(2)]);
		let hash2 = hasher.hash_2([FieldElement::from_u64(2), FieldElement::from_u64(1)]);

		// Order matters: [a, b] ≠ [b, a]
		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_commitment_computation() {
		let hasher = LightPoseidonHasher;

		// Simulate note commitment: H(value, asset_id, owner_pubkey, blinding)
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

		// Simulate nullifier: H(commitment, spending_key)
		let commitment = FieldElement::from_u64(111111);
		let spending_key = FieldElement::from_u64(222222);

		let nullifier = hasher.hash_2([commitment, spending_key]);

		assert!(!nullifier.is_zero());
	}

	#[test]
	fn test_merkle_parent_computation() {
		let hasher = LightPoseidonHasher;

		// Simulate Merkle parent: H(left_child, right_child)
		let left = FieldElement::from_u64(11111);
		let right = FieldElement::from_u64(22222);

		let parent = hasher.hash_2([left, right]);

		assert!(!parent.is_zero());
	}
}
