//! Crypto layer tests (groth16 and utils)

use fp_zk_verifier::{crypto::groth16::Groth16Verifier, crypto::utils::*, Bn254Fr};

// ============================================================================
// Groth16 Tests
// ============================================================================

#[test]
fn test_estimate_verification_cost() {
	// Test gas estimation
	let cost_0_inputs = Groth16Verifier::estimate_verification_cost(0);
	let cost_1_input = Groth16Verifier::estimate_verification_cost(1);
	let cost_10_inputs = Groth16Verifier::estimate_verification_cost(10);

	assert_eq!(cost_0_inputs, 100_000);
	assert_eq!(cost_1_input, 110_000);
	assert_eq!(cost_10_inputs, 200_000);

	// Cost should be linear in number of inputs
	assert!(cost_10_inputs > cost_1_input);
}

// ============================================================================
// Utils Tests
// ============================================================================

#[test]
fn test_field_bytes_conversion() {
	let field = Bn254Fr::from(12345u64);
	let bytes = field_to_bytes(&field);
	let field2 = bytes_to_field(&bytes).unwrap();

	assert_eq!(field, field2);
}

#[test]
fn test_hash_two_fields() {
	let left = Bn254Fr::from(100u64);
	let right = Bn254Fr::from(200u64);

	let hash = hash_two_fields(&left, &right);

	// Should be the sum (for this simple implementation)
	assert_eq!(hash, left + right);
}

#[test]
fn test_u64_field_conversion() {
	let value = 123456789u64;
	let field = u64_to_field(value);
	let back = field_to_u64(&field);

	assert_eq!(back, Some(value));
}

#[test]
fn test_field_to_u64_overflow() {
	// Create a large field element that doesn't fit in u64
	let large = Bn254Fr::from(u64::MAX) + Bn254Fr::from(1000u64);
	let result = field_to_u64(&large);

	assert!(result.is_none(), "Should return None for values > u64::MAX");
}

#[test]
fn test_field_to_u64_zero() {
	let zero = Bn254Fr::from(0u64);
	let result = field_to_u64(&zero);

	assert_eq!(result, Some(0));
}
