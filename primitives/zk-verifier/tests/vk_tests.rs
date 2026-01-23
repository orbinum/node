//! Verification key tests

use fp_zk_verifier::{
	vk::registry::*, CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, TRANSFER_PUBLIC_INPUTS,
	UNSHIELD_PUBLIC_INPUTS,
};

// ============================================================================
// VK Registry Tests
// ============================================================================

#[test]
fn test_get_vk_by_circuit_id_transfer() {
	let vk = get_vk_by_circuit_id(CIRCUIT_ID_TRANSFER);
	assert!(vk.is_ok());
}

#[test]
fn test_get_vk_by_circuit_id_unshield() {
	let vk = get_vk_by_circuit_id(CIRCUIT_ID_UNSHIELD);
	assert!(vk.is_ok());
}

#[test]
fn test_get_vk_by_circuit_id_invalid() {
	let vk = get_vk_by_circuit_id(99);
	assert!(vk.is_err());
	assert!(matches!(
		vk,
		Err(fp_zk_verifier::VerifierError::InvalidCircuitId(99))
	));
}

#[test]
fn test_get_public_input_count_transfer() {
	let count = get_public_input_count(CIRCUIT_ID_TRANSFER);
	assert_eq!(count, Ok(TRANSFER_PUBLIC_INPUTS));
}

#[test]
fn test_get_public_input_count_unshield() {
	let count = get_public_input_count(CIRCUIT_ID_UNSHIELD);
	assert_eq!(count, Ok(UNSHIELD_PUBLIC_INPUTS));
}

#[test]
fn test_validate_public_input_count_valid() {
	let result = validate_public_input_count(CIRCUIT_ID_TRANSFER, TRANSFER_PUBLIC_INPUTS);
	assert!(result.is_ok());
}

#[test]
fn test_validate_public_input_count_invalid() {
	let result = validate_public_input_count(CIRCUIT_ID_TRANSFER, 3);
	assert!(result.is_err());
}

// ============================================================================
// VK Structure Tests
// ============================================================================

#[test]
fn test_transfer_vk_structure() {
	use fp_zk_verifier::vk::get_transfer_vk;

	let vk = get_transfer_vk();

	// Verify all points are on curve
	assert!(vk.alpha_g1.is_on_curve(), "alpha_g1 not on curve");
	assert!(vk.beta_g2.is_on_curve(), "beta_g2 not on curve");
	assert!(vk.gamma_g2.is_on_curve(), "gamma_g2 not on curve");
	assert!(vk.delta_g2.is_on_curve(), "delta_g2 not on curve");

	for (i, ic) in vk.gamma_abc_g1.iter().enumerate() {
		assert!(ic.is_on_curve(), "IC[{i}] not on curve");
	}

	// Transfer has 5 public inputs + 1 for constant = 6 IC points
	assert_eq!(vk.gamma_abc_g1.len(), 6, "Wrong number of IC points");
}

#[test]
fn test_unshield_vk_structure() {
	use fp_zk_verifier::vk::get_unshield_vk;

	let vk = get_unshield_vk();

	// Verify all points are on curve
	assert!(vk.alpha_g1.is_on_curve(), "alpha_g1 not on curve");
	assert!(vk.beta_g2.is_on_curve(), "beta_g2 not on curve");
	assert!(vk.gamma_g2.is_on_curve(), "gamma_g2 not on curve");
	assert!(vk.delta_g2.is_on_curve(), "delta_g2 not on curve");

	for (i, ic) in vk.gamma_abc_g1.iter().enumerate() {
		assert!(ic.is_on_curve(), "IC[{i}] not on curve");
	}

	// Unshield has 4 public inputs + 1 for constant = 5 IC points
	assert_eq!(vk.gamma_abc_g1.len(), 5, "Wrong number of IC points");
}

#[test]
fn test_transfer_vk_bytes_serialization() {
	use fp_zk_verifier::vk::get_transfer_vk_bytes;

	let bytes = get_transfer_vk_bytes();

	// Verify bytes are non-empty
	assert!(!bytes.is_empty(), "VK bytes should not be empty");

	// ark_serialize compressed format:
	// - G1 compressed: 32 bytes each
	// - G2 compressed: 64 bytes each
	// - Vector length prefix: 8 bytes (usize for gamma_abc_g1 count)
	// Total: 32 (alpha) + 64 (beta) + 64 (gamma) + 64 (delta) + 8 (len) + (32 * 6 IC points)
	let expected_size = 32 + 64 + 64 + 64 + 8 + (32 * 6);
	assert_eq!(bytes.len(), expected_size, "Unexpected VK bytes size");
}

#[test]
fn test_unshield_vk_bytes_serialization() {
	use fp_zk_verifier::vk::get_unshield_vk_bytes;

	let bytes = get_unshield_vk_bytes();

	// Verify bytes are non-empty
	assert!(!bytes.is_empty(), "VK bytes should not be empty");

	// ark_serialize compressed format:
	// Total: 32 (alpha) + 64 (beta) + 64 (gamma) + 64 (delta) + 8 (len) + (32 * 5 IC points)
	let expected_size = 32 + 64 + 64 + 64 + 8 + (32 * 5);
	assert_eq!(bytes.len(), expected_size, "Unexpected VK bytes size");
}
