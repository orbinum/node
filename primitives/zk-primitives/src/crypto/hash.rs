//! # Poseidon Hash Function
//!
//! Poseidon is a ZK-friendly hash function optimized for use in ZK-SNARK circuits.
//! It uses ~300 constraints vs ~25,000 for SHA-256.
//!
//! This implementation uses `light-poseidon` which is **compatible with circomlib/iden3**,
//! ensuring that hashes computed here match those from circom circuits.
//!
//! ## Architecture
//!
//! Poseidon uses a sponge construction with:
//! - State width t = inputs + 1 (capacity element)
//! - S-Box: x^5 (alpha = 5)
//! - Full rounds (R_F): 8 (4 at start, 4 at end)
//! - Partial rounds (R_P): varies by input size (57 for 2 inputs)
//! - MDS matrix and round constants from circomlib
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_primitives::crypto::hash::poseidon_hash_2;
//! use ark_bn254::Fr;
//!
//! // Native hash (no constraints)
//! let hash = poseidon_hash_2(&[Fr::from(1u64), Fr::from(2u64)]);
//! ```
//!
//! ## References
//!
//! - Poseidon paper: https://eprint.iacr.org/2019/458.pdf
//! - circomlib: https://github.com/iden3/circomlib
//! - light-poseidon: https://github.com/Lightprotocol/light-poseidon

use crate::core::types::Bn254Fr;

// Re-export light-poseidon for direct access
pub use light_poseidon::Poseidon;
use light_poseidon::PoseidonHasher;

// ============================================================================
// Native Hash Functions (no constraints)
// ============================================================================

/// Poseidon hash for 2 inputs (native, no constraints)
///
/// **Compatible with circomlib's Poseidon(2)**
///
/// This is the standard hash used for:
/// - Merkle tree sibling hashing
/// - Nullifier computation: H(commitment, secret)
///
/// # Example
///
/// ```rust,ignore
/// let hash = poseidon_hash_2(&[Fr::from(1u64), Fr::from(2u64)]);
/// // hash == "7853200120776062878684798364095072458815029376092732009249414926327459813530"
/// ```
pub fn poseidon_hash_2(inputs: &[Bn254Fr; 2]) -> Bn254Fr {
	let mut hasher = Poseidon::<Bn254Fr>::new_circom(2).expect("Could not create Poseidon hasher");
	hasher
		.hash(inputs)
		.expect("Poseidon hash failed for 2 inputs")
}

/// Poseidon hash for 4 inputs (native, no constraints)
///
/// **Compatible with circomlib's Poseidon(4)**
///
/// This is the standard hash used for:
/// - Note commitment: H(value, asset_id, owner_pubkey, blinding)
pub fn poseidon_hash_4(inputs: &[Bn254Fr; 4]) -> Bn254Fr {
	let mut hasher = Poseidon::<Bn254Fr>::new_circom(4).expect("Could not create Poseidon hasher");
	hasher
		.hash(inputs)
		.expect("Poseidon hash failed for 4 inputs")
}

/// Generic Poseidon hash for 1-16 inputs (native)
///
/// Supports variable number of inputs up to 16 (circomlib limit).
pub fn poseidon_hash(inputs: &[Bn254Fr]) -> Result<Bn254Fr, &'static str> {
	if inputs.is_empty() || inputs.len() > 16 {
		return Err("Poseidon supports 1-16 inputs");
	}
	let mut hasher = Poseidon::<Bn254Fr>::new_circom(inputs.len())
		.map_err(|_| "Could not create Poseidon hasher")?;
	hasher.hash(inputs).map_err(|_| "Poseidon hash failed")
}
