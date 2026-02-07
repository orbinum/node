//! Asset management use cases
//!
//! Handles registration, verification, and management of assets in the pool.
//!
//! # Use Cases
//!
//! - **Register Asset**: Register new assets in the shielded pool
//! - **Verify Asset**: Mark an asset as verified for shielded operations
//! - **Unverify Asset**: Mark an asset as unverified, preventing new shields
//! - **Get Asset Metadata**: Retrieve asset information
//! - **Check Asset Verification**: Verify if an asset is approved for use

use crate::{
	domain::entities::AssetMetadata,
	infrastructure::repositories::asset_repository::AssetRepository,
	pallet::{Config, Error, Event, Pallet},
};
use frame_support::{BoundedVec, pallet_prelude::*};
use frame_system::pallet_prelude::BlockNumberFor;

/// Asset management use cases
pub struct AssetManagementUseCase;

impl AssetManagementUseCase {
	/// Register a new asset for use in the shielded pool
	///
	/// Creates a new asset entry in the registry with metadata.
	/// The asset starts as unverified and must be verified by governance before use.
	///
	/// # Arguments
	/// * `name` - Human-readable asset name (e.g., "Tether USD")
	/// * `symbol` - Asset symbol (e.g., "USDT")
	/// * `decimals` - Number of decimal places (e.g., 18)
	/// * `contract_address` - Optional ERC20 contract address
	/// * `creator` - Account registering the asset
	///
	/// # Returns
	/// * `Ok(asset_id)` - The newly created asset ID
	/// * `Err` - If registration fails
	///
	/// # Domain Rules
	/// - Asset ID must be unique (auto-incremented)
	/// - Name must not be empty
	/// - Symbol must be 1-16 characters
	/// - Asset starts unverified
	pub fn register_asset<T: Config>(
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		contract_address: Option<[u8; 20]>,
		creator: T::AccountId,
	) -> Result<u32, DispatchError> {
		// Validate inputs
		ensure!(!name.is_empty(), Error::<T>::InvalidAmount);
		ensure!(!symbol.is_empty(), Error::<T>::InvalidAmount);

		// Get next asset ID
		let asset_id = AssetRepository::increment_asset_id::<T>();
		let current_block = frame_system::Pallet::<T>::block_number();

		// Create asset metadata entity
		let metadata = AssetMetadata {
			id: asset_id,
			name: name.clone(),
			symbol: symbol.clone(),
			decimals,
			is_verified: false, // Starts unverified
			contract_address,
			created_at: current_block,
			creator: creator.clone(),
		};

		// Store in repository
		AssetRepository::store_asset::<T>(asset_id, metadata);

		// Emit event
		Pallet::<T>::deposit_event(Event::AssetRegistered { asset_id });

		Ok(asset_id)
	}

	/// Verify an asset for shielded operations
	///
	/// Marks an asset as verified, allowing it to be used in shield/unshield operations.
	/// Only governance can verify assets.
	///
	/// # Arguments
	/// * `asset_id` - The asset to verify
	///
	/// # Errors
	/// * `InvalidAssetId` - Asset does not exist
	///
	/// # Domain Rules
	/// - Asset must exist in registry
	/// - Only governance can verify
	/// - Verification is required before shield/unshield operations
	pub fn verify_asset<T: Config>(asset_id: u32) -> DispatchResult {
		// Ensure asset exists
		let exists = AssetRepository::exists::<T>(asset_id);
		ensure!(exists, Error::<T>::InvalidAssetId);

		// Update verification status
		let success = AssetRepository::set_verified::<T>(asset_id, true);
		ensure!(success, Error::<T>::InvalidAssetId);

		// Emit event
		Pallet::<T>::deposit_event(Event::AssetVerified { asset_id });

		Ok(())
	}

	/// Unverify an asset
	///
	/// Marks an asset as unverified, preventing new shield operations.
	/// Existing private notes with this asset can still be spent.
	///
	/// # Arguments
	/// * `asset_id` - The asset to unverify
	///
	/// # Errors
	/// * `InvalidAssetId` - Asset does not exist
	///
	/// # Domain Rules
	/// - Asset must exist in registry
	/// - Only governance can unverify
	/// - Existing notes remain spendable
	pub fn unverify_asset<T: Config>(asset_id: u32) -> DispatchResult {
		// Ensure asset exists
		let exists = AssetRepository::exists::<T>(asset_id);
		ensure!(exists, Error::<T>::InvalidAssetId);

		// Update verification status
		let success = AssetRepository::set_verified::<T>(asset_id, false);
		ensure!(success, Error::<T>::InvalidAssetId);

		// Emit event
		Pallet::<T>::deposit_event(Event::AssetUnverified { asset_id });

		Ok(())
	}

	/// Get asset metadata
	///
	/// Retrieves the metadata for a registered asset.
	///
	/// # Arguments
	/// * `asset_id` - The asset to query
	///
	/// # Returns
	/// * `Some(metadata)` - If asset exists
	/// * `None` - If asset not found
	pub fn get_asset_metadata<T: Config>(
		asset_id: u32,
	) -> Option<AssetMetadata<T::AccountId, BlockNumberFor<T>>> {
		AssetRepository::get_asset::<T>(asset_id)
	}

	/// Check if asset is verified
	///
	/// Verifies that an asset is both registered and verified for use.
	///
	/// # Arguments
	/// * `asset_id` - The asset to check
	///
	/// # Returns
	/// * `Ok(())` - Asset is verified
	/// * `Err(InvalidAssetId)` - Asset not found
	/// * `Err(AssetNotVerified)` - Asset exists but not verified
	pub fn ensure_asset_verified<T: Config>(asset_id: u32) -> DispatchResult {
		let metadata =
			AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;

		ensure!(metadata.is_verified, Error::<T>::AssetNotVerified);

		Ok(())
	}

	/// Get next available asset ID
	///
	/// Returns the next asset ID that will be used for registration.
	///
	/// # Returns
	/// The next available asset ID
	pub fn get_next_asset_id<T: Config>() -> u32 {
		AssetRepository::get_next_asset_id::<T>()
	}

	/// Validate asset metadata
	///
	/// Validates that asset metadata meets domain requirements.
	///
	/// # Arguments
	/// * `name` - Asset name
	/// * `symbol` - Asset symbol
	/// * `decimals` - Number of decimals
	///
	/// # Returns
	/// * `Ok(())` - Metadata is valid
	/// * `Err` - Validation failed
	///
	/// # Domain Rules
	/// - Name must not be empty and ≤ 64 bytes
	/// - Symbol must be 1-16 characters
	/// - Decimals typically 0-18 (not enforced)
	pub fn validate_metadata<T: Config>(
		name: &BoundedVec<u8, ConstU32<64>>,
		symbol: &BoundedVec<u8, ConstU32<16>>,
		_decimals: u8,
	) -> DispatchResult {
		// Validate name
		ensure!(!name.is_empty(), Error::<T>::InvalidAmount);
		ensure!(name.len() <= 64, Error::<T>::InvalidAmount);

		// Validate symbol
		ensure!(
			!symbol.is_empty() && symbol.len() <= 16,
			Error::<T>::InvalidAmount
		);

		// Note: decimals is typically 0-18 but we don't enforce this
		// as some exotic tokens may have different values

		Ok(())
	}
}
