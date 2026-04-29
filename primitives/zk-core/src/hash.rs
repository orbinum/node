//! Poseidon hash trait and concrete implementations.
//!
//! - [`PoseidonHasher`]: abstraction for circuit-compatible hashing (testable via mocks).
//! - [`LightPoseidonHasher`]: WASM-compatible implementation using `light-poseidon-nostd`.
//! - [`NativePoseidonHasher`]: native host-function implementation (~3× faster, runtime only).
//! - [`poseidon_hash_1`]: single-input Poseidon used for viewing-key derivation.

use crate::types::FieldElement;
use ark_bn254::Fr;
use light_poseidon_nostd::{Poseidon, PoseidonHasher as LightHasher};

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Abstraction over Poseidon hash implementations.
///
/// Arities exposed map to different Circom circuits:
/// - `hash_2`: Merkle node hashing and nullifier computation.
/// - `hash_4`: Note commitment computation.
/// - `hash_5`: EdDSA-Poseidon challenge hash `h = Poseidon5(R8x, R8y, Ax, Ay, msg)`.
pub trait PoseidonHasher {
	fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement;
	fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement;
	fn hash_5(&self, inputs: [FieldElement; 5]) -> FieldElement;
}

// ─── LightPoseidonHasher ──────────────────────────────────────────────────────

/// WASM-compatible Poseidon hasher using `light-poseidon-nostd`.
///
/// Use this in runtime (WASM) contexts or when native host functions are unavailable.
#[derive(Debug, Clone, Copy, Default)]
pub struct LightPoseidonHasher;

impl PoseidonHasher for LightPoseidonHasher {
	fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
		let result = Poseidon::<Fr>::new_circom(2)
			.expect("Poseidon init (2 inputs) failed")
			.hash(&[inputs[0].inner(), inputs[1].inner()])
			.expect("Poseidon hash_2 failed");
		FieldElement::new(result)
	}

	fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
		let result = Poseidon::<Fr>::new_circom(4)
			.expect("Poseidon init (4 inputs) failed")
			.hash(&[
				inputs[0].inner(),
				inputs[1].inner(),
				inputs[2].inner(),
				inputs[3].inner(),
			])
			.expect("Poseidon hash_4 failed");
		FieldElement::new(result)
	}

	fn hash_5(&self, inputs: [FieldElement; 5]) -> FieldElement {
		let result = Poseidon::<Fr>::new_circom(5)
			.expect("Poseidon init (5 inputs) failed")
			.hash(&[
				inputs[0].inner(),
				inputs[1].inner(),
				inputs[2].inner(),
				inputs[3].inner(),
				inputs[4].inner(),
			])
			.expect("Poseidon hash_5 failed");
		FieldElement::new(result)
	}
}

// ─── NativePoseidonHasher ────────────────────────────────────────────────────

/// Native Poseidon hasher that delegates to `sp-runtime-interface` host functions.
///
/// Provides ~3× performance over the WASM implementation. Only available in a
/// native runtime build (enabled via the `poseidon-native` feature).
#[cfg(feature = "poseidon-native")]
#[derive(Debug, Clone, Copy, Default)]
pub struct NativePoseidonHasher;

#[cfg(feature = "poseidon-native")]
impl PoseidonHasher for NativePoseidonHasher {
	fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
		use crate::host_interface::poseidon_host_interface;
		let left = field_to_bytes(inputs[0].inner());
		let right = field_to_bytes(inputs[1].inner());
		let result = poseidon_host_interface::poseidon_hash_2(&left, &right);
		bytes_to_field(&result)
	}

	fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
		use crate::host_interface::poseidon_host_interface;
		let b1 = field_to_bytes(inputs[0].inner());
		let b2 = field_to_bytes(inputs[1].inner());
		let b3 = field_to_bytes(inputs[2].inner());
		let b4 = field_to_bytes(inputs[3].inner());
		let result = poseidon_host_interface::poseidon_hash_4(&b1, &b2, &b3, &b4);
		bytes_to_field(&result)
	}

	// No host function for 5 inputs — fall back to WASM Poseidon impl.
	fn hash_5(&self, inputs: [FieldElement; 5]) -> FieldElement {
		LightPoseidonHasher.hash_5(inputs)
	}
}

#[cfg(feature = "poseidon-native")]
fn field_to_bytes(field: Fr) -> [u8; 32] {
	use ark_ff::{BigInteger, PrimeField};
	let bytes = field.into_bigint().to_bytes_le();
	let mut result = [0u8; 32];
	result.copy_from_slice(&bytes[..32]);
	result
}

#[cfg(feature = "poseidon-native")]
fn bytes_to_field(bytes: &[u8]) -> FieldElement {
	use ark_ff::PrimeField;
	let mut arr = [0u8; 32];
	arr.copy_from_slice(&bytes[..32]);
	FieldElement::new(Fr::from_le_bytes_mod_order(&arr))
}

// ─── poseidon_hash_1 ──────────────────────────────────────────────────────────

/// Poseidon hash of a single field element.
///
/// Used in the disclosure circuit to derive a viewing key:
/// `viewing_key = Poseidon(owner_pubkey)`.
///
/// Single-input Poseidon is intentionally not part of [`PoseidonHasher`] because
/// it is only needed for the disclosure circuit.
pub fn poseidon_hash_1(input: FieldElement) -> FieldElement {
	let result = Poseidon::<Fr>::new_circom(1)
		.expect("Poseidon init (1 input) failed")
		.hash(&[input.inner()])
		.expect("Poseidon hash_1 failed");
	FieldElement::new(result)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;

	// --- LightPoseidonHasher ---

	#[test]
	fn hash_2_non_zero() {
		let h = LightPoseidonHasher;
		let result = h.hash_2([FieldElement::from_u64(1), FieldElement::from_u64(2)]);
		assert!(!result.is_zero());
	}

	#[test]
	fn hash_4_non_zero() {
		let h = LightPoseidonHasher;
		let result = h.hash_4([
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
			FieldElement::from_u64(4),
		]);
		assert!(!result.is_zero());
	}

	#[test]
	fn hash_2_deterministic() {
		let h = LightPoseidonHasher;
		let a = h.hash_2([FieldElement::from_u64(10), FieldElement::from_u64(20)]);
		let b = h.hash_2([FieldElement::from_u64(10), FieldElement::from_u64(20)]);
		assert_eq!(a, b);
	}

	#[test]
	fn hash_2_order_matters() {
		let h = LightPoseidonHasher;
		let a = h.hash_2([FieldElement::from_u64(1), FieldElement::from_u64(2)]);
		let b = h.hash_2([FieldElement::from_u64(2), FieldElement::from_u64(1)]);
		assert_ne!(a, b);
	}

	#[test]
	fn hash_2_different_inputs_differ() {
		let h = LightPoseidonHasher;
		let a = h.hash_2([FieldElement::from_u64(1), FieldElement::from_u64(2)]);
		let b = h.hash_2([FieldElement::from_u64(3), FieldElement::from_u64(4)]);
		assert_ne!(a, b);
	}

	// --- poseidon_hash_1 ---

	#[test]
	fn hash_1_non_zero() {
		assert!(!poseidon_hash_1(FieldElement::from_u64(42)).is_zero());
	}

	#[test]
	fn hash_1_deterministic() {
		let input = FieldElement::from_u64(12345);
		assert_eq!(poseidon_hash_1(input), poseidon_hash_1(input));
	}

	#[test]
	fn hash_1_different_inputs_differ() {
		let a = poseidon_hash_1(FieldElement::from_u64(1));
		let b = poseidon_hash_1(FieldElement::from_u64(2));
		assert_ne!(a, b);
	}

	#[test]
	fn hash_1_differs_from_hash_2_same_input() {
		let input = FieldElement::from_u64(99);
		let h1 = poseidon_hash_1(input);
		let h2 = LightPoseidonHasher.hash_2([input, FieldElement::from_u64(0)]);
		assert_ne!(h1, h2);
	}
}
