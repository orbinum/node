//! Shield use case
//!
//! Handles depositing public tokens into the shielded pool.

use crate::{
	application::services::shield_service::ShieldService,
	domain::Commitment,
	infrastructure::{
		frame_types::EncryptedMemo,
		repositories::{AssetRepository, CommitmentRepository, MerkleRepository},
	},
	pallet::{BalanceOf, Config},
};
use frame_support::pallet_prelude::*;
use sp_runtime::traits::Zero;

/// Shield use case - deposit tokens into the shielded pool
pub struct ShieldUseCase;

impl ShieldUseCase {
	/// Execute shield operation
	///
	/// # Arguments
	/// * `depositor` - Account depositing tokens
	/// * `asset_id` - Asset to shield (0 = native)
	/// * `amount` - Amount to shield
	/// * `commitment` - Commitment to the new note
	/// * `encrypted_memo` - Encrypted memo for note recovery
	///
	/// # Returns
	/// Result with () on success
	///
	/// # Process
	/// 1. Validate inputs at use case level
	/// 2. Delegate to ShieldService for execution
	pub fn execute<T: Config>(
		depositor: T::AccountId,
		asset_id: u32,
		amount: BalanceOf<T>,
		commitment: Commitment,
		encrypted_memo: EncryptedMemo,
	) -> DispatchResult {
		// Validate inputs at use case level
		Self::validate_inputs::<T>(&amount, &commitment, &encrypted_memo)?;

		// Delegate to shield service
		ShieldService::execute::<T>(depositor, asset_id, amount, commitment, encrypted_memo)
	}

	/// Validate shield inputs
	fn validate_inputs<T: Config>(
		amount: &BalanceOf<T>,
		commitment: &Commitment,
		encrypted_memo: &EncryptedMemo,
	) -> Result<(), DispatchError> {
		use crate::pallet::Error;

		// Check amount is not zero
		if amount.is_zero() {
			return Err(Error::<T>::AmountTooSmall.into());
		}

		// Check commitment is not zero
		if commitment.is_zero() {
			return Err(DispatchError::Other("Invalid commitment (cannot be zero)"));
		}

		// Check memo is not empty
		if encrypted_memo.is_empty() {
			return Err(Error::<T>::InvalidMemoSize.into());
		}

		Ok(())
	}

	/// Check if a commitment already exists
	pub fn commitment_exists<T: Config>(commitment: &Commitment) -> bool {
		CommitmentRepository::exists::<T>(commitment)
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

	/// Get current Merkle tree size
	pub fn get_tree_size<T: Config>() -> u32 {
		MerkleRepository::get_tree_size::<T>()
	}

	/// Get current Merkle root
	pub fn get_current_merkle_root<T: Config>() -> [u8; 32] {
		MerkleRepository::get_root::<T>()
	}

	/// Check if tree has capacity for new leaf
	pub fn has_tree_capacity<T: Config>() -> bool {
		let current_size = MerkleRepository::get_tree_size::<T>();
		let max_leaves = 2u32.saturating_pow(T::MaxTreeDepth::get());
		current_size < max_leaves
	}
}
