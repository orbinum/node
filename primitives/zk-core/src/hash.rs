//! Poseidon hash trait and concrete implementations.
//!
//! - [`PoseidonHasher`]: abstraction for circuit-compatible hashing (testable via mocks).
//! - [`LightPoseidonHasher`]: WASM-compatible implementation using `light-poseidon-nostd`.
//! - [`NativePoseidonHasher`]: native host-function implementation (~3× faster, runtime only).
//! - [`poseidon_hash_1`]: single-input Poseidon used for viewing-key derivation.

use crate::types::FieldElement;
use ark_bn254::Fr;
use light_poseidon_nostd::{Poseidon, PoseidonHasher as LightHasher};

// ─── Circom Poseidon core ───────────────────────────────────────────────────────

/// Compute the circomlib Poseidon hash for a fixed arity.
///
/// # Consensus determinism
///
/// This is the ONLY place that invokes `light-poseidon-nostd`. Both the WASM path
/// ([`LightPoseidonHasher`]) and the native path ([`NativePoseidonHasher`], via the
/// host function that internally calls `LightPoseidonHasher`) go through here, so
/// their behavior is identical by construction.
///
/// # Invariant (why it cannot fail)
///
/// - `new_circom(nr_inputs)` only fails with `InvalidWidthCircom` when
///   `nr_inputs + 1 > MAX_X5_LEN (= 13)`. The arities in use (1, 2, 4, 5) yield
///   width 2/3/5/6, always valid.
/// - `hash(&inputs)` only fails with `InvalidNumberOfInputs` when
///   `inputs.len() != nr_inputs`. Callers pass fixed-length arrays matching the
///   arity.
///
/// Inputs are already-reduced `Fr` (not raw bytes), so no parsing/range error
/// variant applies.
///
/// # Failure behavior (unreachable)
///
/// If the invariant were ever violated (a programming bug), we return a
/// **deterministic** value instead of `panic!`. This guarantees native and WASM
/// never diverge in behavior: a native `panic!` aborts the node process while in
/// WASM it is a recoverable trap — a divergence that would break consensus. Never
/// introduce `.expect()`/`panic!` in this path.
///
/// The fallback is deliberately NOT zero: a zero commitment/nullifier is the dummy
/// sentinel elsewhere in the system, so a zero fallback could be silently skipped
/// (e.g. an unspent nullifier). We return a fixed non-zero domain-separated marker
/// so any downstream use of a fallback value stands out rather than masquerading as
/// a dummy. This value is never produced by a real Poseidon hash of valid inputs in
/// practice, and the branch is unreachable regardless.
#[inline]
fn poseidon_circom(nr_inputs: usize, inputs: &[Fr]) -> Fr {
	debug_assert_eq!(
		inputs.len(),
		nr_inputs,
		"poseidon_circom: arity mismatch (broken invariant)"
	);
	match Poseidon::<Fr>::new_circom(nr_inputs).and_then(|mut p| p.hash(inputs)) {
		Ok(result) => result,
		// Unreachable with constant arity and `Fr` inputs (see invariant above).
		// Non-zero deterministic marker: identical on native and WASM, never panics,
		// and never collides with the all-zero dummy sentinel.
		Err(_) => Fr::from(POSEIDON_FALLBACK_MARKER_U64),
	}
}

/// Non-zero, deterministic fallback for the unreachable Poseidon failure branch.
/// Chosen so it cannot be confused with the all-zero dummy sentinel.
const POSEIDON_FALLBACK_MARKER_U64: u64 = 0xDEAD_BEEF_DEAD_BEEF;

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
		let result = poseidon_circom(2, &[inputs[0].inner(), inputs[1].inner()]);
		FieldElement::new(result)
	}

	fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
		let result = poseidon_circom(
			4,
			&[
				inputs[0].inner(),
				inputs[1].inner(),
				inputs[2].inner(),
				inputs[3].inner(),
			],
		);
		FieldElement::new(result)
	}

	fn hash_5(&self, inputs: [FieldElement; 5]) -> FieldElement {
		let result = poseidon_circom(
			5,
			&[
				inputs[0].inner(),
				inputs[1].inner(),
				inputs[2].inner(),
				inputs[3].inner(),
				inputs[4].inner(),
			],
		);
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
	let n = bytes.len().min(32);
	result[..n].copy_from_slice(&bytes[..n]);
	result
}

#[cfg(feature = "poseidon-native")]
fn bytes_to_field(bytes: &[u8]) -> FieldElement {
	use ark_ff::PrimeField;
	let mut arr = [0u8; 32];
	let n = bytes.len().min(32);
	arr[..n].copy_from_slice(&bytes[..n]);
	FieldElement::new(Fr::from_le_bytes_mod_order(&arr))
}

// ─── poseidon_hash_1 ──────────────────────────────────────────────────────────

/// Poseidon hash of a single field element.
///
/// Used in the `value_proof` circuit to derive the owner key hash:
/// `owner_hash = Poseidon(owner_pubkey)`.
///
/// Single-input Poseidon is intentionally not part of [`PoseidonHasher`] because
/// it is only needed for the value_proof circuit.
pub fn poseidon_hash_1(input: FieldElement) -> FieldElement {
	let result = poseidon_circom(1, &[input.inner()]);
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

	// ─── No panic on boundary inputs, deterministic behavior ───────────────────

	/// `Fr = p - 1`, the largest canonical field element. Must not panic or diverge.
	fn field_max() -> FieldElement {
		use ark_ff::Field;
		// -1 in the field == p - 1.
		FieldElement::new(-Fr::ONE)
	}

	#[test]
	fn hash_no_panic_on_boundary_inputs() {
		let h = LightPoseidonHasher;
		let zero = FieldElement::zero();
		let max = field_max();
		// None of these calls must panic (they previously used `.expect()`).
		let _ = h.hash_2([zero, max]);
		let _ = h.hash_2([max, max]);
		let _ = h.hash_4([zero, max, zero, max]);
		let _ = h.hash_5([max, max, max, max, max]);
		let _ = poseidon_hash_1(max);
	}

	#[test]
	fn hash_boundary_inputs_are_deterministic() {
		let h = LightPoseidonHasher;
		let max = field_max();
		assert_eq!(h.hash_2([max, max]), h.hash_2([max, max]));
		assert_eq!(
			h.hash_4([max, max, max, max]),
			h.hash_4([max, max, max, max])
		);
		assert_eq!(poseidon_hash_1(max), poseidon_hash_1(max));
	}

	#[test]
	fn poseidon_circom_core_matches_trait() {
		// The internal core and the trait produce the same result (shared path).
		let a = FieldElement::from_u64(7);
		let b = FieldElement::from_u64(11);
		let via_trait = LightPoseidonHasher.hash_2([a, b]);
		let via_core = FieldElement::new(poseidon_circom(2, &[a.inner(), b.inner()]));
		assert_eq!(via_trait, via_core);
	}

	// ─── Defensive 32-byte conversion (no panic on short/long) ─────────────────

	#[cfg(feature = "poseidon-native")]
	#[test]
	fn field_to_bytes_roundtrips_boundary_values() {
		use ark_ff::Field;
		// 0, 1, and p-1 must all round-trip through the 32-byte conversion.
		for f in [Fr::from(0u64), Fr::from(1u64), -Fr::ONE] {
			let bytes = field_to_bytes(f);
			assert_eq!(bytes.len(), 32);
			let back = bytes_to_field(&bytes);
			assert_eq!(back, FieldElement::new(f));
		}
	}

	#[cfg(feature = "poseidon-native")]
	#[test]
	fn bytes_to_field_no_panic_on_short_or_long() {
		// Shorter and longer inputs must not panic (previously copy_from_slice would).
		let _ = bytes_to_field(&[1u8, 2, 3]);
		let _ = bytes_to_field(&[]);
		let _ = bytes_to_field(&[0xABu8; 40]);
	}

	#[test]
	fn fallback_marker_is_non_zero() {
		// The unreachable failure branch must never yield the all-zero dummy sentinel.
		assert_ne!(super::POSEIDON_FALLBACK_MARKER_U64, 0);
		assert!(!FieldElement::new(Fr::from(super::POSEIDON_FALLBACK_MARKER_U64)).is_zero());
	}
}
