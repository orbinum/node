//! Tests for commitment

use crate::domain::entities::Commitment;
use sp_core::H256;

#[test]
fn test_commitment_creation() {
	let bytes = [1u8; 32];
	let commitment = Commitment::new(bytes);
	assert_eq!(commitment.as_bytes(), &bytes);
}

#[test]
fn test_commitment_validity() {
	// Commitment válido (no es todo ceros)
	let valid = Commitment::new([1u8; 32]);
	assert!(valid.is_valid());

	// Commitment inválido (todo ceros)
	let invalid = Commitment::default();
	assert!(!invalid.is_valid());
}

#[test]
fn test_commitment_from_h256() {
	let h256 = H256::from([42u8; 32]);
	let commitment = Commitment::from(h256);
	assert_eq!(commitment.as_bytes(), &[42u8; 32]);
}

#[test]
fn test_commitment_equality() {
	let c1 = Commitment::new([5u8; 32]);
	let c2 = Commitment::new([5u8; 32]);
	let c3 = Commitment::new([6u8; 32]);

	assert_eq!(c1, c2);
	assert_ne!(c1, c3);
}
