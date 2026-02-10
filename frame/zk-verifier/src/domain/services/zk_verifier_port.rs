//! ZK Verifier Port (Interface)
//!
//! This trait defines the port (in hexagonal architecture terms) for
//! ZK proof verification. Other pallets can use this trait as a dependency
//! without coupling to the concrete implementation.

use sp_runtime::DispatchError;

/// Domain port for ZK proof verification
pub trait ZkVerifierPort {
	/// Verify a private transfer proof
	///
	/// # Arguments
	/// * `proof` - Serialized proof bytes
	/// * `merkle_root` - Merkle tree root used in the proof
	/// * `nullifiers` - Nullifiers of consumed notes
	/// * `commitments` - Commitments of newly created notes
	///
	/// # Returns
	/// * `Ok(true)` if the proof is valid
	/// * `Ok(false)` if the proof is invalid
	/// * `Err` if an error occurs during verification
	fn verify_transfer_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifiers: &[[u8; 32]],
		commitments: &[[u8; 32]],
		version: Option<u32>,
	) -> Result<bool, DispatchError>;

	/// Verify an unshield proof (pool withdrawal)
	///
	/// # Arguments
	/// * `proof` - Serialized proof bytes
	/// * `merkle_root` - Merkle tree root used in the proof
	/// * `nullifier` - Nullifier of the consumed note
	/// * `amount` - Amount to withdraw (part of public input)
	/// * `recipient` - Recipient address (20 bytes for H160)
	/// * `asset_id` - Asset ID (u32)
	/// * `version` - Circuit version (None for active version)
	///
	/// # Returns
	/// * `Ok(true)` if the proof is valid
	/// * `Ok(false)` if the proof is invalid
	/// * `Err` if an error occurs during verification
	fn verify_unshield_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifier: &[u8; 32],
		amount: u128,
		version: Option<u32>,
	) -> Result<bool, DispatchError>;

	/// Verify a disclosure proof (selective disclosure)
	///
	/// # Arguments
	/// * `proof` - Serialized Groth16 proof bytes
	/// * `public_signals` - Public signals of the disclosure
	/// * `version` - Circuit version (None for active version)
	///
	/// # Returns
	/// * `Ok(true)` if the proof is valid
	/// * `Ok(false)` if the proof is invalid
	/// * `Err` if an error occurs during verification
	fn verify_disclosure_proof(
		proof: &[u8],
		public_signals: &[u8],
		version: Option<u32>,
	) -> Result<bool, DispatchError>;

	/// Verify multiple disclosure proofs in batch (optimized)
	///
	/// # Arguments
	/// * `proofs` - Vector of serialized Groth16 proofs
	/// * `public_signals` - Vector of public signals (one per proof)
	/// * `version` - Circuit version (None for active version)
	///   ...
	fn batch_verify_disclosure_proofs(
		proofs: &[sp_std::vec::Vec<u8>],
		public_signals: &[sp_std::vec::Vec<u8>],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;
}
