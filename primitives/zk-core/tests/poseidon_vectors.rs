//! Known-answer vectors for the Poseidon hashers and native/WASM equivalence.
//!
//! The expected values are the canonical circomlib (iden3) Poseidon outputs over
//! BN254 for the given inputs, encoded big-endian. If `light-poseidon-nostd` ever
//! ships different parameters than the compiled Circom circuit, these vectors fail
//! — which is the whole point: every proof and every Merkle root in the system
//! depends on this hash matching the circuit exactly.

use ark_ff::{BigInteger, PrimeField};
use orbinum_zk_core::{poseidon_hash_1, FieldElement, LightPoseidonHasher, PoseidonHasher};

/// Big-endian 32-byte hex of a field element.
fn to_hex_be(fe: FieldElement) -> String {
	let bytes = fe.inner().into_bigint().to_bytes_be();
	let mut s = String::from("0x");
	for b in &bytes {
		s.push_str(&format!("{b:02x}"));
	}
	s
}

fn fe(n: u64) -> FieldElement {
	FieldElement::from_u64(n)
}

// ─── Known-answer vectors (canonical circomlib BN254 Poseidon) ─────────────────

/// Poseidon([1]) — single input (used for owner_hash in the value_proof circuit).
const P1_1: &str = "0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133";
/// Poseidon([1, 2]) — arity 2 (Merkle node / nullifier).
const P2_1_2: &str = "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
/// Poseidon([1, 2, 3, 4]) — arity 4 (note commitment).
const P4_1_2_3_4: &str = "0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465";
/// Poseidon([1, 2, 3, 4, 5]) — arity 5 (EdDSA challenge).
const P5_1_2_3_4_5: &str = "0x0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0";

#[test]
fn poseidon_1_matches_circomlib() {
	assert_eq!(to_hex_be(poseidon_hash_1(fe(1))), P1_1);
}

#[test]
fn poseidon_2_matches_circomlib() {
	let h = LightPoseidonHasher;
	assert_eq!(to_hex_be(h.hash_2([fe(1), fe(2)])), P2_1_2);
}

#[test]
fn poseidon_4_matches_circomlib() {
	let h = LightPoseidonHasher;
	assert_eq!(
		to_hex_be(h.hash_4([fe(1), fe(2), fe(3), fe(4)])),
		P4_1_2_3_4
	);
}

#[test]
fn poseidon_5_matches_circomlib() {
	let h = LightPoseidonHasher;
	assert_eq!(
		to_hex_be(h.hash_5([fe(1), fe(2), fe(3), fe(4), fe(5)])),
		P5_1_2_3_4_5
	);
}

// ─── Native ≡ WASM equivalence ─────────────────────────────────────────────────
//
// `NativePoseidonHasher` routes through the `sp-runtime-interface` host function,
// which serializes field elements to bytes and back. This exercises that
// bytes↔field boundary — the place a native/WASM divergence would actually surface
// — against the WASM `LightPoseidonHasher` for a spread of inputs.

#[cfg(feature = "poseidon-native")]
#[test]
fn native_matches_wasm_hash_2() {
	use orbinum_zk_core::NativePoseidonHasher;
	let native = NativePoseidonHasher;
	let wasm = LightPoseidonHasher;
	for (a, b) in [(0u64, 0u64), (1, 2), (7, 11), (u64::MAX, 1), (12345, 67890)] {
		assert_eq!(
			native.hash_2([fe(a), fe(b)]),
			wasm.hash_2([fe(a), fe(b)]),
			"native≠wasm for hash_2({a},{b})"
		);
	}
}

#[cfg(feature = "poseidon-native")]
#[test]
fn native_matches_wasm_hash_4() {
	use orbinum_zk_core::NativePoseidonHasher;
	let native = NativePoseidonHasher;
	let wasm = LightPoseidonHasher;
	for base in [0u64, 1, 999, u64::MAX] {
		let inputs = [
			fe(base),
			fe(base ^ 0xff),
			fe(base.wrapping_add(1)),
			fe(base / 2),
		];
		assert_eq!(
			native.hash_4(inputs),
			wasm.hash_4(inputs),
			"native≠wasm for hash_4 base={base}"
		);
	}
}

#[cfg(feature = "poseidon-native")]
#[test]
fn native_matches_wasm_and_vectors() {
	use orbinum_zk_core::NativePoseidonHasher;
	// Native path must also match the circomlib known-answer vectors.
	let native = NativePoseidonHasher;
	assert_eq!(to_hex_be(native.hash_2([fe(1), fe(2)])), P2_1_2);
	assert_eq!(
		to_hex_be(native.hash_4([fe(1), fe(2), fe(3), fe(4)])),
		P4_1_2_3_4
	);
}
