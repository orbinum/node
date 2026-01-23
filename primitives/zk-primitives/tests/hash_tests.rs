//! Integration tests for Poseidon hash functions

use ark_bn254::Fr as Bn254Fr;
use ark_std::str::FromStr;
use fp_zk_primitives::crypto::hash::*;

#[test]
fn test_poseidon_hash_2_deterministic() {
	let input1 = Bn254Fr::from(1u64);
	let input2 = Bn254Fr::from(2u64);

	let hash1 = poseidon_hash_2(&[input1, input2]);
	let hash2 = poseidon_hash_2(&[input1, input2]);

	assert_eq!(hash1, hash2, "Poseidon should be deterministic");
}

#[test]
fn test_poseidon_hash_2_order_matters() {
	let a = Bn254Fr::from(1u64);
	let b = Bn254Fr::from(2u64);

	let hash1 = poseidon_hash_2(&[a, b]);
	let hash2 = poseidon_hash_2(&[b, a]);

	assert_ne!(hash1, hash2, "Order of inputs should matter");
}

#[test]
fn test_poseidon_hash_2_circomlib_compatibility() {
	let input1 = Bn254Fr::from(1u64);
	let input2 = Bn254Fr::from(2u64);

	let hash = poseidon_hash_2(&[input1, input2]);
	let expected = Bn254Fr::from_str(
		"7853200120776062878684798364095072458815029376092732009249414926327459813530",
	)
	.expect("Invalid expected value");

	assert_eq!(hash, expected, "Hash should match circomlib reference");
}

#[test]
fn test_poseidon_hash_4_deterministic() {
	let inputs = [
		Bn254Fr::from(1u64),
		Bn254Fr::from(2u64),
		Bn254Fr::from(3u64),
		Bn254Fr::from(4u64),
	];

	let hash1 = poseidon_hash_4(&inputs);
	let hash2 = poseidon_hash_4(&inputs);

	assert_eq!(hash1, hash2, "Poseidon should be deterministic");
}

#[test]
fn test_poseidon_hash_4_different_inputs() {
	let inputs1 = [
		Bn254Fr::from(1u64),
		Bn254Fr::from(2u64),
		Bn254Fr::from(3u64),
		Bn254Fr::from(4u64),
	];
	let inputs2 = [
		Bn254Fr::from(1u64),
		Bn254Fr::from(2u64),
		Bn254Fr::from(3u64),
		Bn254Fr::from(5u64),
	];

	let hash1 = poseidon_hash_4(&inputs1);
	let hash2 = poseidon_hash_4(&inputs2);

	assert_ne!(
		hash1, hash2,
		"Different inputs should produce different hashes"
	);
}

#[test]
fn test_poseidon_hash_generic() {
	let inputs = vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)];
	let hash = poseidon_hash(&inputs).expect("Hash should succeed");
	let hash2 = poseidon_hash_2(&[Bn254Fr::from(1u64), Bn254Fr::from(2u64)]);

	assert_eq!(hash, hash2, "Generic and specialized versions should match");
}

#[test]
fn test_poseidon_hash_empty_inputs() {
	let inputs: Vec<Bn254Fr> = vec![];
	let result = poseidon_hash(&inputs);

	assert!(result.is_err(), "Empty inputs should fail");
	assert_eq!(result.unwrap_err(), "Poseidon supports 1-16 inputs");
}

#[test]
fn test_poseidon_hash_too_many_inputs() {
	let inputs = vec![Bn254Fr::from(1u64); 17];
	let result = poseidon_hash(&inputs);

	assert!(result.is_err(), "More than 16 inputs should fail");
	assert_eq!(result.unwrap_err(), "Poseidon supports 1-16 inputs");
}

#[test]
fn test_poseidon_hash_variable_inputs() {
	// Test with different input sizes (light-poseidon supports 1-12)
	for size in 1..=12 {
		let inputs: Vec<Bn254Fr> = (0..size).map(|i| Bn254Fr::from(i as u64)).collect();
		let hash = poseidon_hash(&inputs);
		assert!(hash.is_ok(), "Hash with {} inputs should succeed", size);
		assert_ne!(
			hash.unwrap(),
			Bn254Fr::from(0u64),
			"Hash should be non-zero"
		);
	}
}

#[test]
fn test_poseidon_hash_collision_resistance() {
	// Different inputs should produce different outputs
	let hash1 = poseidon_hash_2(&[Bn254Fr::from(1u64), Bn254Fr::from(2u64)]);
	let hash2 = poseidon_hash_2(&[Bn254Fr::from(1u64), Bn254Fr::from(3u64)]);
	let hash3 = poseidon_hash_2(&[Bn254Fr::from(2u64), Bn254Fr::from(1u64)]);

	assert_ne!(hash1, hash2);
	assert_ne!(hash1, hash3);
	assert_ne!(hash2, hash3);
}

#[test]
fn test_poseidon_hash_zero_inputs() {
	let hash = poseidon_hash_2(&[Bn254Fr::from(0u64), Bn254Fr::from(0u64)]);
	assert_ne!(
		hash,
		Bn254Fr::from(0u64),
		"Hash of zeros should be non-zero"
	);
}
