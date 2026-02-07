//! Tests for nullifier

use crate::domain::entities::Nullifier;
use sp_core::H256;

#[test]
fn test_nullifier_creation() {
	let bytes = [255u8; 32];
	let nullifier = Nullifier::new(bytes);
	assert_eq!(nullifier.as_bytes(), &bytes);
}

#[test]
fn test_nullifier_validation() {
	// Nullifier válido
	let valid = Nullifier::new([1u8; 32]);
	assert!(valid.validate());

	// Nullifier inválido (todo ceros)
	let invalid = Nullifier::default();
	assert!(!invalid.validate());
}

#[test]
fn test_nullifier_from_h256() {
	let h256 = H256::from([99u8; 32]);
	let nullifier = Nullifier::from(h256);
	assert_eq!(nullifier.as_bytes(), &[99u8; 32]);
}

#[test]
fn test_nullifier_equality() {
	let n1 = Nullifier::new([7u8; 32]);
	let n2 = Nullifier::new([7u8; 32]);
	let n3 = Nullifier::new([8u8; 32]);

	assert_eq!(n1, n2);
	assert_ne!(n1, n3);
}

#[test]
fn test_nullifier_uniqueness() {
	// Dos nullifiers diferentes deben ser diferentes
	let n1 = Nullifier::new([1u8; 32]);
	let n2 = Nullifier::new([2u8; 32]);
	assert_ne!(n1, n2);
}
