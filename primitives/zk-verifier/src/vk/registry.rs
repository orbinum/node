//! Centralized Verification Key Registry
//!
//! This module provides runtime lookup of verification keys by circuit ID.

use crate::core::{
	constants::{
		CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS,
	},
	error::VerifierError,
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
