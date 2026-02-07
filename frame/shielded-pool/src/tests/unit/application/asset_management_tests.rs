//! Asset Management Use Case Tests
//!
//! Unit tests for asset management use cases including:
//! - Asset registration
//! - Asset verification
//! - Asset metadata validation

use crate::{Error, application::use_cases::asset_management::AssetManagementUseCase, mock::*};
use frame_support::{BoundedVec, assert_noop, assert_ok};

#[test]
fn register_asset_creates_valid_metadata() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Bitcoin".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"BTC".to_vec()).unwrap();
		let decimals = 8u8;
		let contract_address = Some([0x42u8; 20]);
		let creator = 1u64;

		let result = AssetManagementUseCase::register_asset::<Test>(
			name.clone(),
			symbol.clone(),
			decimals,
			contract_address,
			creator,
		);

		assert_ok!(result);
		let asset_id = result.unwrap();

		// Verify asset was created with correct ID
		assert_eq!(asset_id, 1); // First asset (0 is native)

		// Verify metadata
		let metadata = AssetManagementUseCase::get_asset_metadata::<Test>(asset_id);
		assert!(metadata.is_some());

		let metadata = metadata.unwrap();
		assert_eq!(metadata.id, asset_id);
		assert_eq!(metadata.name, name);
		assert_eq!(metadata.symbol, symbol);
		assert_eq!(metadata.decimals, decimals);
		assert!(!metadata.is_verified); // Starts unverified
		assert_eq!(metadata.contract_address, contract_address);
		assert_eq!(metadata.creator, creator);
	});
}

#[test]
fn register_asset_increments_asset_id() {
	new_test_ext().execute_with(|| {
		let name1 = BoundedVec::try_from(b"Asset1".to_vec()).unwrap();
		let symbol1 = BoundedVec::try_from(b"AS1".to_vec()).unwrap();
		let name2 = BoundedVec::try_from(b"Asset2".to_vec()).unwrap();
		let symbol2 = BoundedVec::try_from(b"AS2".to_vec()).unwrap();
		let creator = 1u64;

		// Register first asset
		let asset_id_1 =
			AssetManagementUseCase::register_asset::<Test>(name1, symbol1, 18, None, creator)
				.unwrap();

		// Register second asset
		let asset_id_2 =
			AssetManagementUseCase::register_asset::<Test>(name2, symbol2, 18, None, creator)
				.unwrap();

		// Asset IDs should increment
		assert_eq!(asset_id_1, 1);
		assert_eq!(asset_id_2, 2);

		// Next asset ID should be 3
		assert_eq!(AssetManagementUseCase::get_next_asset_id::<Test>(), 3);
	});
}

#[test]
fn register_asset_with_empty_name_fails() {
	new_test_ext().execute_with(|| {
		let empty_name = BoundedVec::try_from(b"".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"TST".to_vec()).unwrap();
		let creator = 1u64;

		let result =
			AssetManagementUseCase::register_asset::<Test>(empty_name, symbol, 18, None, creator);

		assert_noop!(result, Error::<Test>::InvalidAmount);
	});
}

#[test]
fn register_asset_with_empty_symbol_fails() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Test Asset".to_vec()).unwrap();
		let empty_symbol = BoundedVec::try_from(b"".to_vec()).unwrap();
		let creator = 1u64;

		let result =
			AssetManagementUseCase::register_asset::<Test>(name, empty_symbol, 18, None, creator);

		assert_noop!(result, Error::<Test>::InvalidAmount);
	});
}

#[test]
fn verify_asset_marks_as_verified() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Ethereum".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"ETH".to_vec()).unwrap();
		let creator = 1u64;

		// Register asset
		let asset_id =
			AssetManagementUseCase::register_asset::<Test>(name, symbol, 18, None, creator)
				.unwrap();

		// Verify it starts unverified
		let metadata_before = AssetManagementUseCase::get_asset_metadata::<Test>(asset_id).unwrap();
		assert!(!metadata_before.is_verified);

		// Verify asset
		assert_ok!(AssetManagementUseCase::verify_asset::<Test>(asset_id));

		// Check it's now verified
		let metadata_after = AssetManagementUseCase::get_asset_metadata::<Test>(asset_id).unwrap();
		assert!(metadata_after.is_verified);
	});
}

#[test]
fn verify_nonexistent_asset_fails() {
	new_test_ext().execute_with(|| {
		let nonexistent_id = 999u32;

		let result = AssetManagementUseCase::verify_asset::<Test>(nonexistent_id);

		assert_noop!(result, Error::<Test>::InvalidAssetId);
	});
}

#[test]
fn unverify_asset_marks_as_unverified() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Cardano".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"ADA".to_vec()).unwrap();
		let creator = 1u64;

		// Register and verify asset
		let asset_id =
			AssetManagementUseCase::register_asset::<Test>(name, symbol, 18, None, creator)
				.unwrap();
		assert_ok!(AssetManagementUseCase::verify_asset::<Test>(asset_id));

		// Verify it's verified
		let metadata_verified =
			AssetManagementUseCase::get_asset_metadata::<Test>(asset_id).unwrap();
		assert!(metadata_verified.is_verified);

		// Unverify asset
		assert_ok!(AssetManagementUseCase::unverify_asset::<Test>(asset_id));

		// Check it's now unverified
		let metadata_unverified =
			AssetManagementUseCase::get_asset_metadata::<Test>(asset_id).unwrap();
		assert!(!metadata_unverified.is_verified);
	});
}

#[test]
fn unverify_nonexistent_asset_fails() {
	new_test_ext().execute_with(|| {
		let nonexistent_id = 999u32;

		let result = AssetManagementUseCase::unverify_asset::<Test>(nonexistent_id);

		assert_noop!(result, Error::<Test>::InvalidAssetId);
	});
}

#[test]
fn ensure_asset_verified_accepts_verified_asset() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Polkadot".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"DOT".to_vec()).unwrap();
		let creator = 1u64;

		// Register and verify asset
		let asset_id =
			AssetManagementUseCase::register_asset::<Test>(name, symbol, 10, None, creator)
				.unwrap();
		assert_ok!(AssetManagementUseCase::verify_asset::<Test>(asset_id));

		// Should accept verified asset
		assert_ok!(AssetManagementUseCase::ensure_asset_verified::<Test>(
			asset_id
		));
	});
}

#[test]
fn ensure_asset_verified_rejects_unverified_asset() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Solana".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"SOL".to_vec()).unwrap();
		let creator = 1u64;

		// Register but don't verify asset
		let asset_id =
			AssetManagementUseCase::register_asset::<Test>(name, symbol, 9, None, creator).unwrap();

		// Should reject unverified asset
		assert_noop!(
			AssetManagementUseCase::ensure_asset_verified::<Test>(asset_id),
			Error::<Test>::AssetNotVerified
		);
	});
}

#[test]
fn ensure_asset_verified_rejects_nonexistent_asset() {
	new_test_ext().execute_with(|| {
		let nonexistent_id = 999u32;

		assert_noop!(
			AssetManagementUseCase::ensure_asset_verified::<Test>(nonexistent_id),
			Error::<Test>::InvalidAssetId
		);
	});
}

#[test]
fn get_asset_metadata_returns_none_for_nonexistent() {
	new_test_ext().execute_with(|| {
		let nonexistent_id = 999u32;

		let result = AssetManagementUseCase::get_asset_metadata::<Test>(nonexistent_id);

		assert!(result.is_none());
	});
}

#[test]
fn validate_metadata_accepts_valid_inputs() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Valid Asset".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"VAL".to_vec()).unwrap();
		let decimals = 18u8;

		let result = AssetManagementUseCase::validate_metadata::<Test>(&name, &symbol, decimals);

		assert_ok!(result);
	});
}

#[test]
fn validate_metadata_rejects_empty_name() {
	new_test_ext().execute_with(|| {
		let empty_name = BoundedVec::try_from(b"".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"TST".to_vec()).unwrap();

		let result = AssetManagementUseCase::validate_metadata::<Test>(&empty_name, &symbol, 18);

		assert_noop!(result, Error::<Test>::InvalidAmount);
	});
}

#[test]
fn validate_metadata_rejects_empty_symbol() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Test".to_vec()).unwrap();
		let empty_symbol = BoundedVec::try_from(b"".to_vec()).unwrap();

		let result = AssetManagementUseCase::validate_metadata::<Test>(&name, &empty_symbol, 18);

		assert_noop!(result, Error::<Test>::InvalidAmount);
	});
}

#[test]
fn validate_metadata_accepts_max_length_name() {
	new_test_ext().execute_with(|| {
		// Create 64-byte name (max length)
		let name = BoundedVec::try_from(vec![b'A'; 64]).unwrap();
		let symbol = BoundedVec::try_from(b"TST".to_vec()).unwrap();

		let result = AssetManagementUseCase::validate_metadata::<Test>(&name, &symbol, 18);

		assert_ok!(result);
	});
}

#[test]
fn validate_metadata_accepts_max_length_symbol() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Test".to_vec()).unwrap();
		// Create 16-byte symbol (max length)
		let symbol = BoundedVec::try_from(vec![b'S'; 16]).unwrap();

		let result = AssetManagementUseCase::validate_metadata::<Test>(&name, &symbol, 18);

		assert_ok!(result);
	});
}

#[test]
fn validate_metadata_accepts_various_decimals() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Test".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"TST".to_vec()).unwrap();

		// Test common decimal values
		for decimals in [0, 6, 8, 9, 10, 12, 18].iter() {
			let result =
				AssetManagementUseCase::validate_metadata::<Test>(&name, &symbol, *decimals);
			assert_ok!(result);
		}
	});
}

#[test]
fn get_next_asset_id_returns_correct_value() {
	new_test_ext().execute_with(|| {
		// Initially should be 1 (0 is native)
		assert_eq!(AssetManagementUseCase::get_next_asset_id::<Test>(), 1);

		// Register an asset
		let name = BoundedVec::try_from(b"Test".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"TST".to_vec()).unwrap();
		let creator = 1u64;

		AssetManagementUseCase::register_asset::<Test>(name, symbol, 18, None, creator).unwrap();

		// Should now be 2
		assert_eq!(AssetManagementUseCase::get_next_asset_id::<Test>(), 2);
	});
}

#[test]
fn asset_registration_preserves_all_fields() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Test Token with Long Name".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"TTLN".to_vec()).unwrap();
		let decimals = 12u8;
		let contract_address = Some([0xAB; 20]);
		let creator = 42u64;

		let asset_id = AssetManagementUseCase::register_asset::<Test>(
			name.clone(),
			symbol.clone(),
			decimals,
			contract_address,
			creator,
		)
		.unwrap();

		let metadata = AssetManagementUseCase::get_asset_metadata::<Test>(asset_id).unwrap();

		// Verify all fields are preserved
		assert_eq!(metadata.id, asset_id);
		assert_eq!(metadata.name, name);
		assert_eq!(metadata.symbol, symbol);
		assert_eq!(metadata.decimals, decimals);
		assert_eq!(metadata.contract_address, contract_address);
		assert_eq!(metadata.creator, creator);
		assert!(!metadata.is_verified);
		assert!(metadata.created_at > 0); // Block number should be set
	});
}
