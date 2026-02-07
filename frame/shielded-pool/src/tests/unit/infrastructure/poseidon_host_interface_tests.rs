//! Tests para Poseidon Host Interface (OPT-2)
//!
//! Estos tests verifican que:
//! 1. La implementación WASM de Poseidon produce resultados correctos
//! 2. El orden de los inputs afecta el resultado (no es conmutativo)
//! 3. Las funciones hash_2 y hash_4 funcionan correctamente
//!
//! **Nota:** Los host functions nativos requieren un runtime completo con externalities.
//! Estos tests solo validan la implementación WASM subyacente que usan los host functions.

use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use orbinum_zk_core::{
	domain::{ports::PoseidonHasher, value_objects::FieldElement},
	infrastructure::crypto::LightPoseidonHasher,
};

#[test]
fn test_poseidon_hash_2_produces_valid_output() {
	let left = [1u8; 32];
	let right = [2u8; 32];

	// Convert and hash using WASM
	let left_fr = Bn254Fr::from_le_bytes_mod_order(&left);
	let right_fr = Bn254Fr::from_le_bytes_mod_order(&right);

	// Use the hasher through the trait
	let hasher = LightPoseidonHasher;
	let hash_fr = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);

	// Convert back to bytes
	let mut hash_bytes = [0u8; 32];
	let bigint = hash_fr.inner().into_bigint();
	let bytes = bigint.to_bytes_le();
	hash_bytes.copy_from_slice(&bytes[..32]);

	// Hash should be non-zero
	assert_ne!(
		hash_bytes, [0u8; 32],
		"Poseidon hash should produce non-zero output"
	);
}

#[test]
fn test_poseidon_hash_2_order_matters() {
	let left = [1u8; 32];
	let right = [2u8; 32];

	// Hash both orders
	let left_fr = Bn254Fr::from_le_bytes_mod_order(&left);
	let right_fr = Bn254Fr::from_le_bytes_mod_order(&right);

	let hasher = LightPoseidonHasher;
	let hash1_fr = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);
	let hash2_fr = hasher.hash_2([FieldElement::new(right_fr), FieldElement::new(left_fr)]);

	// Convert both to bytes
	let mut hash1 = [0u8; 32];
	let bigint1 = hash1_fr.inner().into_bigint();
	hash1.copy_from_slice(&bigint1.to_bytes_le()[..32]);

	let mut hash2 = [0u8; 32];
	let bigint2 = hash2_fr.inner().into_bigint();
	hash2.copy_from_slice(&bigint2.to_bytes_le()[..32]);

	// Hashes should be different
	assert_ne!(
		hash1, hash2,
		"Poseidon hash should depend on input order (not commutative)"
	);
}

#[test]
fn test_poseidon_hash_4_produces_valid_output() {
	let inputs_bytes = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

	// Convert all to field elements
	let inputs_fr: [Bn254Fr; 4] = [
		Bn254Fr::from_le_bytes_mod_order(&inputs_bytes[0]),
		Bn254Fr::from_le_bytes_mod_order(&inputs_bytes[1]),
		Bn254Fr::from_le_bytes_mod_order(&inputs_bytes[2]),
		Bn254Fr::from_le_bytes_mod_order(&inputs_bytes[3]),
	];

	let hasher = LightPoseidonHasher;
	let hash_fr = hasher.hash_4([
		FieldElement::new(inputs_fr[0]),
		FieldElement::new(inputs_fr[1]),
		FieldElement::new(inputs_fr[2]),
		FieldElement::new(inputs_fr[3]),
	]);

	// Convert to bytes
	let mut hash = [0u8; 32];
	let bigint = hash_fr.inner().into_bigint();
	hash.copy_from_slice(&bigint.to_bytes_le()[..32]);

	// Hash should be non-zero
	assert_ne!(
		hash, [0u8; 32],
		"Poseidon hash_4 should produce non-zero output"
	);
}

#[test]
fn test_poseidon_hash_2_deterministic() {
	let left = [42u8; 32];
	let right = [99u8; 32];

	// Hash twice with same inputs
	let left_fr = Bn254Fr::from_le_bytes_mod_order(&left);
	let right_fr = Bn254Fr::from_le_bytes_mod_order(&right);

	let hasher = LightPoseidonHasher;
	let hash1_fr = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);
	let hash2_fr = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);

	// Should be identical
	assert_eq!(
		hash1_fr, hash2_fr,
		"Poseidon hash should be deterministic (same inputs = same output)"
	);
}

#[test]
fn test_poseidon_hash_4_deterministic() {
	let inputs_bytes = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

	let inputs_fr: [Bn254Fr; 4] = [
		Bn254Fr::from_le_bytes_mod_order(&inputs_bytes[0]),
		Bn254Fr::from_le_bytes_mod_order(&inputs_bytes[1]),
		Bn254Fr::from_le_bytes_mod_order(&inputs_bytes[2]),
		Bn254Fr::from_le_bytes_mod_order(&inputs_bytes[3]),
	];

	let hasher = LightPoseidonHasher;
	let hash1_fr = hasher.hash_4([
		FieldElement::new(inputs_fr[0]),
		FieldElement::new(inputs_fr[1]),
		FieldElement::new(inputs_fr[2]),
		FieldElement::new(inputs_fr[3]),
	]);
	let hash2_fr = hasher.hash_4([
		FieldElement::new(inputs_fr[0]),
		FieldElement::new(inputs_fr[1]),
		FieldElement::new(inputs_fr[2]),
		FieldElement::new(inputs_fr[3]),
	]);

	assert_eq!(
		hash1_fr, hash2_fr,
		"Poseidon hash_4 should be deterministic"
	);
}

#[test]
fn test_poseidon_hash_2_different_inputs_different_outputs() {
	let left1 = [1u8; 32];
	let right1 = [2u8; 32];

	let left2 = [3u8; 32];
	let right2 = [4u8; 32];

	let left1_fr = Bn254Fr::from_le_bytes_mod_order(&left1);
	let right1_fr = Bn254Fr::from_le_bytes_mod_order(&right1);

	let hasher = LightPoseidonHasher;
	let hash1_fr = hasher.hash_2([FieldElement::new(left1_fr), FieldElement::new(right1_fr)]);

	let left2_fr = Bn254Fr::from_le_bytes_mod_order(&left2);
	let right2_fr = Bn254Fr::from_le_bytes_mod_order(&right2);
	let hash2_fr = hasher.hash_2([FieldElement::new(left2_fr), FieldElement::new(right2_fr)]);

	assert_ne!(
		hash1_fr, hash2_fr,
		"Different inputs should produce different hashes (collision resistance)"
	);
}
