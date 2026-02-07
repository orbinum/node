//! Unshield use case
//!
//! Handles withdrawing tokens from the shielded pool to a public account.

use crate::{
	application::services::unshield_service::UnshieldService,
	domain::Nullifier,
	infrastructure::repositories::{AssetRepository, MerkleRepository, NullifierRepository},
	pallet::{BalanceOf, Config},
};
use frame_support::pallet_prelude::*;
use sp_runtime::traits::Zero;

/// Unshield use case - withdraw tokens from the shielded pool
pub struct UnshieldUseCase;

impl UnshieldUseCase {
	/// Execute the unshield operation
	///
	/// # Arguments
	/// * `proof` - Zero-knowledge proof of note ownership
	/// * `merkle_root` - Merkle root the proof is based on
	/// * `nullifier` - Nullifier to prevent double-spending
	/// * `asset_id` - Which asset to unshield
	/// * `amount` - Amount to withdraw
	/// * `recipient` - Public account to receive the tokens
	///
	/// # Returns
	/// Result with () on success
	///
	/// # Process
	/// 1. Validate inputs at use case level
	/// 2. Delegate to UnshieldService for execution
	pub fn execute<T: Config>(
		proof: &[u8],
		merkle_root: [u8; 32],
		nullifier: Nullifier,
		asset_id: u32,
		amount: BalanceOf<T>,
		recipient: T::AccountId,
	) -> DispatchResult {
		// Validate inputs at use case level
		Self::validate_inputs::<T>(&amount, &nullifier, &recipient)?;

		// Delegate to unshield service
		UnshieldService::execute::<T>(proof, merkle_root, nullifier, asset_id, amount, recipient)
	}

	/// Validate unshield inputs
	fn validate_inputs<T: Config>(
		amount: &BalanceOf<T>,
		nullifier: &Nullifier,
		_recipient: &T::AccountId,
	) -> Result<(), DispatchError> {
		use crate::pallet::Error;

		// Check amount is not zero
		if amount.is_zero() {
			return Err(Error::<T>::InvalidAmount.into());
		}

		// Check nullifier is valid (not all zeros)
		if !nullifier.validate() {
			return Err(DispatchError::Other("Invalid nullifier (cannot be zero)"));
		}

		// Recipient validation is done in service layer (pool account check)

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

	/// Check if an asset exists
	pub fn asset_exists<T: Config>(asset_id: u32) -> bool {
		AssetRepository::exists::<T>(asset_id)
	}

	/// Check if an asset is verified
	pub fn is_asset_verified<T: Config>(asset_id: u32) -> bool {
		if let Some(asset) = AssetRepository::get_asset::<T>(asset_id) {
			asset.is_verified
		} else {
			false
		}
	}

	/// Get current Merkle root
	pub fn get_current_merkle_root<T: Config>() -> [u8; 32] {
		MerkleRepository::get_root::<T>()
	}

	/// Get Merkle tree size
	pub fn get_tree_size<T: Config>() -> u32 {
		MerkleRepository::get_tree_size::<T>()
	}
}
