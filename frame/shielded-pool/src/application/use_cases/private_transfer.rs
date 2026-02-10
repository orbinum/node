//! Private transfer use case
//!
//! Handles transferring value privately within the shielded pool.

use crate::{
	application::services::transfer_service::TransferService,
	domain::{Commitment, Nullifier},
	infrastructure::{
		frame_types::EncryptedMemo,
		repositories::{MerkleRepository, NullifierRepository},
	},
	pallet::Config,
};
use frame_support::{BoundedVec, pallet_prelude::*};

/// Private transfer use case - transfer within the shielded pool
pub struct PrivateTransferUseCase;

impl PrivateTransferUseCase {
	/// Execute a private transfer
	///
	/// # Arguments
	/// * `proof` - ZK proof of valid transfer (max 512 bytes)
	/// * `merkle_root` - Merkle root used in proof
	/// * `nullifiers` - Spent input commitments (max 2)
	/// * `commitments` - New output commitments (max 2)
	/// * `encrypted_memos` - Encrypted memos for outputs (max 2)
	///
	/// # Returns
	/// Result with () on success
	///
	/// # Process
	/// 1. Validate inputs
	/// 2. Verify the ZK proof
	/// 3. Check input nullifiers haven't been used
	/// 4. Add output commitments to Merkle tree
	/// 5. Mark input nullifiers as used
	/// 6. Store encrypted memos for outputs
	/// 7. Emit event
	pub fn execute<T: Config>(
		proof: BoundedVec<u8, ConstU32<512>>,
		merkle_root: [u8; 32],
		nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
		commitments: BoundedVec<Commitment, ConstU32<2>>,
		encrypted_memos: BoundedVec<EncryptedMemo, ConstU32<2>>,
	) -> DispatchResult {
		// Validate inputs at use case level
		Self::validate_inputs::<T>(&nullifiers, &commitments, &encrypted_memos)?;

		// Delegate to transfer service
		TransferService::execute::<T>(proof, merkle_root, nullifiers, commitments, encrypted_memos)
	}

	/// Validate transfer inputs
	fn validate_inputs<T: Config>(
		nullifiers: &BoundedVec<Nullifier, ConstU32<2>>,
		commitments: &BoundedVec<Commitment, ConstU32<2>>,
		encrypted_memos: &BoundedVec<EncryptedMemo, ConstU32<2>>,
	) -> Result<(), DispatchError> {
		use crate::pallet::Error;

		// Check memos count matches commitments
		if encrypted_memos.len() != commitments.len() {
			return Err(Error::<T>::MemoCommitmentMismatch.into());
		}

		// Check nullifiers are not empty
		if nullifiers.is_empty() {
			return Err(DispatchError::Other("At least one input required"));
		}

		// Check commitments are not empty
		if commitments.is_empty() {
			return Err(DispatchError::Other("At least one output required"));
		}

		// Check nullifiers are unique
		for i in 0..nullifiers.len() {
			for j in (i + 1)..nullifiers.len() {
				if nullifiers[i] == nullifiers[j] {
					return Err(DispatchError::Other("Duplicate nullifiers not allowed"));
				}
			}
		}

		Ok(())
	}

	/// Check if a nullifier has been used
	pub fn is_nullifier_used<T: Config>(nullifier: &Nullifier) -> bool {
		NullifierRepository::is_used::<T>(nullifier)
	}

	/// Check if a Merkle root is known (current or historic)
	pub fn is_merkle_root_known<T: Config>(root: &[u8; 32]) -> bool {
		MerkleRepository::is_known_root::<T>(root)
	}

	/// Get current Merkle root
	pub fn get_current_merkle_root<T: Config>() -> [u8; 32] {
		MerkleRepository::get_poseidon_root::<T>()
	}

	/// Get Merkle tree size
	pub fn get_tree_size<T: Config>() -> u32 {
		MerkleRepository::get_tree_size::<T>()
	}
}
