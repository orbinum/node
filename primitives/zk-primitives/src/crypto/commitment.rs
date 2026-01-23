//! # Commitment Scheme
//!
//! Implements Pedersen-like commitment scheme using Poseidon hash with strong types.
//!
//! ## Commitment
//!
//! A commitment hides a value while allowing later verification:
//! ```text
//! commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
//! ```
//!
//! Properties:
//! - **Hiding**: Cannot determine value without blinding factor
//! - **Binding**: Cannot change value after commitment is created
//!
//! ## Nullifier
//!
//! A nullifier is a unique identifier that marks a note as spent:
//! ```text
//! nullifier = Poseidon(commitment, spending_key)
//! ```
//!
//! Properties:
//! - **Deterministic**: Same inputs → same nullifier
//! - **One-way**: Cannot derive spending_key from nullifier
//! - **Unique**: Each note has exactly one nullifier
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_primitives::crypto::commitment::{create_commitment, compute_nullifier};
//! use fp_zk_primitives::core::types::{Commitment, Nullifier, SpendingKey};
//!
//! // Create a commitment
//! let commitment = create_commitment(value, asset_id, pubkey, blinding);
//!
//! // Compute nullifier when spending
//! let nullifier = compute_nullifier(&commitment, &spending_key);
//! ```

use crate::core::types::{Blinding, Bn254Fr, Commitment, Nullifier, OwnerPubkey, SpendingKey};
use crate::crypto::hash::{poseidon_hash_2, poseidon_hash_4};

// ============================================================================
// Commitment Functions
// ============================================================================

/// Create a note commitment (Pedersen-like commitment using Poseidon)
///
/// # Arguments
///
/// * `value` - The amount in the note
/// * `asset_id` - The asset type identifier
/// * `owner_pubkey` - Public key of the note owner
/// * `blinding` - Random blinding factor for hiding
///
/// # Returns
///
/// The commitment hash (as a strong type)
///
/// # Formula
///
/// ```text
/// commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
/// ```
pub fn create_commitment(
	value: Bn254Fr,
	asset_id: Bn254Fr,
	owner_pubkey: OwnerPubkey,
	blinding: Blinding,
) -> Commitment {
	let hash = poseidon_hash_4(&[value, asset_id, owner_pubkey, blinding]);
	Commitment(hash)
}

/// Compute a nullifier from a commitment
///
/// The nullifier is used to mark a note as spent without revealing
/// which note it is.
///
/// # Arguments
///
/// * `commitment` - The note commitment
/// * `spending_key` - Private key used to spend the note
///
/// # Returns
///
/// The nullifier hash (as a strong type)
///
/// # Formula
///
/// ```text
/// nullifier = Poseidon(commitment, spending_key)
/// ```
pub fn compute_nullifier(commitment: &Commitment, spending_key: &SpendingKey) -> Nullifier {
	let hash = poseidon_hash_2(&[commitment.0, spending_key.0]);
	Nullifier(hash)
}
