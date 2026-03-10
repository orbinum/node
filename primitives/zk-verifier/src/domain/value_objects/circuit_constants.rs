//! Circuit IDs, public input counts, and verification cost constants.

/// Circuit identifier for transfer operations
/// Used to lookup the correct verification key at runtime
pub const CIRCUIT_ID_TRANSFER: u8 = 1;

/// Circuit identifier for unshield (withdraw) operations
/// Used to lookup the correct verification key at runtime
pub const CIRCUIT_ID_UNSHIELD: u8 = 2;

/// Number of public inputs for the transfer circuit
/// Public inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2]
pub const TRANSFER_PUBLIC_INPUTS: usize = 5;

/// Number of public inputs for the unshield circuit
/// Public inputs: [merkle_root, nullifier, recipient, amount, asset_id]
pub const UNSHIELD_PUBLIC_INPUTS: usize = 5;

/// Circuit identifier for disclosure (selective disclosure) operations
/// Used to lookup the correct verification key at runtime
pub const CIRCUIT_ID_DISCLOSURE: u8 = 4;

/// Number of public inputs for the disclosure circuit
/// Public inputs: [commitment, revealed_value, revealed_asset_id, revealed_owner_hash]
pub const DISCLOSURE_PUBLIC_INPUTS: usize = 4;

/// Circuit identifier for private link dispatch operations
/// Used to lookup the correct verification key at runtime
/// Public inputs: [commitment, call_hash_fe]
pub const CIRCUIT_ID_PRIVATE_LINK: u8 = 5;

/// Number of public inputs for the private link circuit
/// Public inputs: [commitment(32B LE field element), call_hash_fe(32B LE field element)]
pub const PRIVATE_LINK_PUBLIC_INPUTS: usize = 2;

/// Base cost for Groth16 verification (pairing operations)
/// This is a reasonable default that can be overridden in runtime configuration
pub const BASE_VERIFICATION_COST: u64 = 100_000;

/// Cost per public input (scalar multiplication)
pub const PER_INPUT_COST: u64 = 10_000;

/// Maximum number of public inputs supported
pub const MAX_PUBLIC_INPUTS: usize = 32;

#[cfg(test)]
mod tests {
	use super::*;
	use core::hint::black_box;

	#[test]
	fn test_circuit_ids_are_stable() {
		assert_eq!(CIRCUIT_ID_TRANSFER, 1);
		assert_eq!(CIRCUIT_ID_UNSHIELD, 2);
		assert_eq!(CIRCUIT_ID_DISCLOSURE, 4);
		assert_eq!(CIRCUIT_ID_PRIVATE_LINK, 5);
	}

	#[test]
	fn test_public_input_counts_are_expected() {
		assert_eq!(TRANSFER_PUBLIC_INPUTS, 5);
		assert_eq!(UNSHIELD_PUBLIC_INPUTS, 5);
		assert_eq!(DISCLOSURE_PUBLIC_INPUTS, 4);
		assert_eq!(PRIVATE_LINK_PUBLIC_INPUTS, 2);
	}

	#[test]
	fn test_cost_constants_are_consistent() {
		let base_verification_cost = black_box(BASE_VERIFICATION_COST);
		let per_input_cost = black_box(PER_INPUT_COST);
		let max_public_inputs = black_box(MAX_PUBLIC_INPUTS);

		assert!(base_verification_cost > 0);
		assert!(per_input_cost > 0);
		assert!(max_public_inputs >= TRANSFER_PUBLIC_INPUTS);
		assert!(max_public_inputs >= UNSHIELD_PUBLIC_INPUTS);
		assert!(max_public_inputs >= DISCLOSURE_PUBLIC_INPUTS);
		assert!(max_public_inputs >= PRIVATE_LINK_PUBLIC_INPUTS);
	}

	#[test]
	fn test_estimated_cost_growth_is_linear() {
		let cost_0 = BASE_VERIFICATION_COST;
		let cost_1 = BASE_VERIFICATION_COST + PER_INPUT_COST;
		let cost_5 = BASE_VERIFICATION_COST + (5 * PER_INPUT_COST);

		assert_eq!(cost_1 - cost_0, PER_INPUT_COST);
		assert_eq!(cost_5 - cost_1, 4 * PER_INPUT_COST);
	}
}
