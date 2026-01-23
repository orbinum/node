//! Integration tests for core types

use ark_bn254::Fr as Bn254Fr;
use fp_zk_primitives::core::types::{Commitment, Nullifier, SpendingKey};

#[test]
fn test_commitment_new() {
	let value = Bn254Fr::from(123u64);
	let commitment = Commitment::new(value);
	assert_eq!(commitment.0, value);
}

#[test]
fn test_commitment_inner() {
	let value = Bn254Fr::from(456u64);
	let commitment = Commitment::new(value);
	assert_eq!(commitment.inner(), value);
}

#[test]
fn test_commitment_from_fr() {
	let value = Bn254Fr::from(789u64);
	let commitment = Commitment::from(value);
	assert_eq!(commitment.0, value);
}

#[test]
fn test_commitment_into_fr() {
	let value = Bn254Fr::from(999u64);
	let commitment = Commitment::new(value);
	let fr: Bn254Fr = commitment.into();
	assert_eq!(fr, value);
}

#[test]
fn test_commitment_equality() {
	let commitment1 = Commitment::new(Bn254Fr::from(100u64));
	let commitment2 = Commitment::new(Bn254Fr::from(100u64));
	let commitment3 = Commitment::new(Bn254Fr::from(200u64));

	assert_eq!(commitment1, commitment2);
	assert_ne!(commitment1, commitment3);
}

#[test]
fn test_commitment_clone() {
	let commitment1 = Commitment::new(Bn254Fr::from(123u64));
	let commitment2 = commitment1.clone();
	assert_eq!(commitment1, commitment2);
}

#[test]
fn test_commitment_debug() {
	let commitment = Commitment::new(Bn254Fr::from(123u64));
	let debug_str = format!("{:?}", commitment);
	assert!(debug_str.contains("Commitment"));
}

#[test]
fn test_nullifier_new() {
	let value = Bn254Fr::from(123u64);
	let nullifier = Nullifier::new(value);
	assert_eq!(nullifier.0, value);
}

#[test]
fn test_nullifier_inner() {
	let value = Bn254Fr::from(456u64);
	let nullifier = Nullifier::new(value);
	assert_eq!(nullifier.inner(), value);
}

#[test]
fn test_nullifier_from_fr() {
	let value = Bn254Fr::from(789u64);
	let nullifier = Nullifier::from(value);
	assert_eq!(nullifier.0, value);
}

#[test]
fn test_nullifier_into_fr() {
	let value = Bn254Fr::from(999u64);
	let nullifier = Nullifier::new(value);
	let fr: Bn254Fr = nullifier.into();
	assert_eq!(fr, value);
}

#[test]
fn test_nullifier_equality() {
	let nullifier1 = Nullifier::new(Bn254Fr::from(100u64));
	let nullifier2 = Nullifier::new(Bn254Fr::from(100u64));
	let nullifier3 = Nullifier::new(Bn254Fr::from(200u64));

	assert_eq!(nullifier1, nullifier2);
	assert_ne!(nullifier1, nullifier3);
}

#[test]
fn test_nullifier_clone() {
	let nullifier1 = Nullifier::new(Bn254Fr::from(123u64));
	let nullifier2 = nullifier1.clone();
	assert_eq!(nullifier1, nullifier2);
}

#[test]
fn test_nullifier_debug() {
	let nullifier = Nullifier::new(Bn254Fr::from(123u64));
	let debug_str = format!("{:?}", nullifier);
	assert!(debug_str.contains("Nullifier"));
}

#[test]
fn test_spending_key_new() {
	let value = Bn254Fr::from(123u64);
	let key = SpendingKey::new(value);
	assert_eq!(key.0, value);
}

#[test]
fn test_spending_key_inner() {
	let value = Bn254Fr::from(456u64);
	let key = SpendingKey::new(value);
	assert_eq!(key.inner(), value);
}

#[test]
fn test_spending_key_from_fr() {
	let value = Bn254Fr::from(789u64);
	let key = SpendingKey::from(value);
	assert_eq!(key.0, value);
}

#[test]
fn test_spending_key_equality() {
	let key1 = SpendingKey::new(Bn254Fr::from(100u64));
	let key2 = SpendingKey::new(Bn254Fr::from(100u64));
	let key3 = SpendingKey::new(Bn254Fr::from(200u64));

	assert_eq!(key1, key2);
	assert_ne!(key1, key3);
}

#[test]
fn test_spending_key_clone() {
	let key1 = SpendingKey::new(Bn254Fr::from(123u64));
	let key2 = key1.clone();
	assert_eq!(key1, key2);
}

#[test]
fn test_spending_key_debug() {
	let key = SpendingKey::new(Bn254Fr::from(123u64));
	let debug_str = format!("{:?}", key);
	assert!(debug_str.contains("SpendingKey"));
}

#[test]
fn test_types_are_distinct() {
	// Verify that different types with same underlying value are not equal
	let value = Bn254Fr::from(123u64);
	let commitment = Commitment::new(value);
	let nullifier = Nullifier::new(value);
	let spending_key = SpendingKey::new(value);

	// All have same underlying value
	assert_eq!(commitment.0, value);
	assert_eq!(nullifier.0, value);
	assert_eq!(spending_key.0, value);

	// But types prevent accidental mixing (enforced at compile time)
	// This won't compile: assert_eq!(commitment, nullifier);
	// This won't compile: assert_eq!(commitment, spending_key);
	// This won't compile: assert_eq!(nullifier, spending_key);
}

#[test]
fn test_commitment_hash_trait() {
	use std::collections::HashSet;

	let mut set = HashSet::new();
	let c1 = Commitment::new(Bn254Fr::from(100u64));
	let c2 = Commitment::new(Bn254Fr::from(100u64));
	let c3 = Commitment::new(Bn254Fr::from(200u64));

	set.insert(c1);
	assert!(set.contains(&c2)); // Same value should be in set
	assert!(!set.contains(&c3)); // Different value should not be in set
}

#[test]
fn test_nullifier_hash_trait() {
	use std::collections::HashSet;

	let mut set = HashSet::new();
	let n1 = Nullifier::new(Bn254Fr::from(100u64));
	let n2 = Nullifier::new(Bn254Fr::from(100u64));
	let n3 = Nullifier::new(Bn254Fr::from(200u64));

	set.insert(n1);
	assert!(set.contains(&n2));
	assert!(!set.contains(&n3));
}

#[test]
fn test_commitment_copy() {
	let c1 = Commitment::new(Bn254Fr::from(100u64));
	let c2 = c1; // Should copy, not move
	assert_eq!(c1, c2);
}

#[test]
fn test_nullifier_copy() {
	let n1 = Nullifier::new(Bn254Fr::from(100u64));
	let n2 = n1; // Should copy, not move
	assert_eq!(n1, n2);
}

#[test]
fn test_types_with_zero_value() {
	let zero = Bn254Fr::from(0u64);
	let commitment = Commitment::new(zero);
	let nullifier = Nullifier::new(zero);
	let spending_key = SpendingKey::new(zero);

	assert_eq!(commitment.0, zero);
	assert_eq!(nullifier.0, zero);
	assert_eq!(spending_key.0, zero);
}

#[test]
fn test_types_with_large_value() {
	let large = Bn254Fr::from(u64::MAX);
	let commitment = Commitment::new(large);
	let nullifier = Nullifier::new(large);
	let spending_key = SpendingKey::new(large);

	assert_eq!(commitment.0, large);
	assert_eq!(nullifier.0, large);
	assert_eq!(spending_key.0, large);
}
