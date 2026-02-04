//! Centralized Verification Key Registry
//!
//! This module provides runtime lookup of verification keys by circuit ID.

use crate::domain::value_objects::{
	circuit_constants::{
		CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS,
	},
	errors::VerifierError,
};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;

/// Get verification key by circuit ID
///
/// # Arguments
///
/// * `circuit_id` - The circuit identifier (1 = transfer, 2 = unshield)
///
/// # Returns
///
/// `Ok(VerifyingKey<Bn254>)` if the circuit ID is valid, `Err(InvalidCircuitId)` otherwise
///
/// # Example
///
/// ```rust,ignore
/// use fp_zk_verifier::vk::registry::get_vk_by_circuit_id;
///
/// let vk = get_vk_by_circuit_id(1)?; // Transfer VK
/// ```
pub fn get_vk_by_circuit_id(circuit_id: u8) -> Result<VerifyingKey<Bn254>, VerifierError> {
	match circuit_id {
		CIRCUIT_ID_TRANSFER => Ok(super::transfer::get_vk()),
		CIRCUIT_ID_UNSHIELD => Ok(super::unshield::get_vk()),
		_ => Err(VerifierError::InvalidCircuitId(circuit_id)),
	}
}

/// Get expected public input count by circuit ID
///
/// # Arguments
///
/// * `circuit_id` - The circuit identifier
///
/// # Returns
///
/// `Ok(usize)` with the expected number of public inputs, or `Err(InvalidCircuitId)`
///
/// # Example
///
/// ```rust,ignore
/// use fp_zk_verifier::vk::registry::get_public_input_count;
///
/// let count = get_public_input_count(1)?; // 5 for transfer
/// assert_eq!(count, 5);
/// ```
pub fn get_public_input_count(circuit_id: u8) -> Result<usize, VerifierError> {
	match circuit_id {
		CIRCUIT_ID_TRANSFER => Ok(TRANSFER_PUBLIC_INPUTS),
		CIRCUIT_ID_UNSHIELD => Ok(UNSHIELD_PUBLIC_INPUTS),
		_ => Err(VerifierError::InvalidCircuitId(circuit_id)),
	}
}

/// Validate that public inputs match expected count for circuit
///
/// # Arguments
///
/// * `circuit_id` - The circuit identifier
/// * `actual_count` - The actual number of public inputs provided
///
/// # Returns
///
/// `Ok(())` if counts match, `Err(InvalidPublicInput)` otherwise
pub fn validate_public_input_count(
	circuit_id: u8,
	actual_count: usize,
) -> Result<(), VerifierError> {
	let expected_count = get_public_input_count(circuit_id)?;
	if actual_count == expected_count {
		Ok(())
	} else {
		Err(VerifierError::InvalidPublicInput)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_get_vk_by_circuit_id_transfer() {
		let result = get_vk_by_circuit_id(CIRCUIT_ID_TRANSFER);
		assert!(result.is_ok());
		let vk = result.unwrap();
		assert_eq!(vk.gamma_abc_g1.len(), TRANSFER_PUBLIC_INPUTS + 1);
	}

	#[test]
	fn test_get_vk_by_circuit_id_unshield() {
		let result = get_vk_by_circuit_id(CIRCUIT_ID_UNSHIELD);
		assert!(result.is_ok());
		let vk = result.unwrap();
		assert_eq!(vk.gamma_abc_g1.len(), UNSHIELD_PUBLIC_INPUTS + 1);
	}

	#[test]
	fn test_get_vk_by_circuit_id_invalid() {
		let result = get_vk_by_circuit_id(99);
		assert!(result.is_err());
		assert!(matches!(result, Err(VerifierError::InvalidCircuitId(99))));
	}

	#[test]
	fn test_get_vk_by_circuit_id_zero() {
		let result = get_vk_by_circuit_id(0);
		assert!(result.is_err());
	}

	#[test]
	fn test_get_public_input_count_transfer() {
		let result = get_public_input_count(CIRCUIT_ID_TRANSFER);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), TRANSFER_PUBLIC_INPUTS);
	}

	#[test]
	fn test_get_public_input_count_unshield() {
		let result = get_public_input_count(CIRCUIT_ID_UNSHIELD);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), UNSHIELD_PUBLIC_INPUTS);
	}

	#[test]
	fn test_get_public_input_count_invalid() {
		let result = get_public_input_count(255);
		assert!(result.is_err());
		assert!(matches!(result, Err(VerifierError::InvalidCircuitId(255))));
	}

	#[test]
	fn test_validate_public_input_count_valid_transfer() {
		let result = validate_public_input_count(CIRCUIT_ID_TRANSFER, TRANSFER_PUBLIC_INPUTS);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_public_input_count_valid_unshield() {
		let result = validate_public_input_count(CIRCUIT_ID_UNSHIELD, UNSHIELD_PUBLIC_INPUTS);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_public_input_count_mismatch() {
		let result = validate_public_input_count(CIRCUIT_ID_TRANSFER, 999);
		assert!(result.is_err());
		assert!(matches!(result, Err(VerifierError::InvalidPublicInput)));
	}

	#[test]
	fn test_validate_public_input_count_zero() {
		let result = validate_public_input_count(CIRCUIT_ID_TRANSFER, 0);
		assert!(result.is_err());
	}

	#[test]
	fn test_validate_public_input_count_invalid_circuit() {
		let result = validate_public_input_count(99, 5);
		assert!(result.is_err());
		assert!(matches!(result, Err(VerifierError::InvalidCircuitId(99))));
	}
}
