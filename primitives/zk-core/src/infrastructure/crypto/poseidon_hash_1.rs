//! Poseidon hash of a single field element.
//!
//! Standalone function used in the disclosure circuit to derive the
//! `viewing_key` from the `owner_pubkey`:
//!   `viewing_key = Poseidon(owner_pubkey)`
//!
//! Single-input Poseidon is intentionally **not** part of the `PoseidonHasher`
//! trait because it is only needed for the disclosure circuit.

use crate::domain::value_objects::FieldElement;
use ark_bn254::Fr;
use light_poseidon_nostd::{Poseidon, PoseidonHasher as LightHasher};

/// Computes the circom-compatible Poseidon hash of a single field element.
pub fn poseidon_hash_1(input: FieldElement) -> FieldElement {
	let result = Poseidon::<Fr>::new_circom(1)
		.expect("Failed to initialize Poseidon with 1 input")
		.hash(&[input.inner()])
		.expect("Poseidon hash_1 failed");

	FieldElement::new(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hash_1_non_zero_output() {
		let h = poseidon_hash_1(FieldElement::from_u64(42));
		assert!(!h.is_zero());
	}

	#[test]
	fn test_hash_1_zero_input_non_zero() {
		// Poseidon of zero is not zero
		let h = poseidon_hash_1(FieldElement::from_u64(0));
		assert!(!h.is_zero());
	}

	#[test]
	fn test_hash_1_deterministic() {
		let input = FieldElement::from_u64(12345);
		assert_eq!(poseidon_hash_1(input), poseidon_hash_1(input));
	}

	#[test]
	fn test_hash_1_different_inputs_different_outputs() {
		let h1 = poseidon_hash_1(FieldElement::from_u64(1));
		let h2 = poseidon_hash_1(FieldElement::from_u64(2));
		assert_ne!(h1, h2);
	}

	#[test]
	fn test_hash_1_large_value() {
		let h = poseidon_hash_1(FieldElement::from_u64(u64::MAX));
		assert!(!h.is_zero());
	}

	#[test]
	fn test_hash_1_differs_from_hash_2_same_input() {
		use crate::domain::ports::PoseidonHasher;
		use crate::infrastructure::crypto::poseidon_hasher::LightPoseidonHasher;

		let input = FieldElement::from_u64(99);
		let h1 = poseidon_hash_1(input);
		let h2 = LightPoseidonHasher.hash_2([input, FieldElement::from_u64(0)]);
		assert_ne!(h1, h2, "hash_1 and hash_2 must produce different results");
	}

	#[test]
	fn test_hash_1_disclosure_viewing_key_derivation() {
		// Simulate: viewing_key = Poseidon(owner_pubkey)
		let owner_pubkey = FieldElement::from_u64(0xDEAD_BEEF);
		let viewing_key = poseidon_hash_1(owner_pubkey);
		assert!(!viewing_key.is_zero());
		// Idempotent derivation
		assert_eq!(viewing_key, poseidon_hash_1(owner_pubkey));
	}

	#[test]
	fn test_hash_1_multiple_sequential_calls() {
		let input = FieldElement::from_u64(777);
		let results: alloc::vec::Vec<_> = (0..5).map(|_| poseidon_hash_1(input)).collect();
		for r in &results[1..] {
			assert_eq!(*r, results[0]);
		}
	}
}
