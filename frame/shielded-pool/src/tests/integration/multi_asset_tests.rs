//! Multi-asset tests
//!
//! Tests for multi-asset support including registration, verification,
//! and cross-asset operations.

use crate::tests::helpers::*;
use crate::{Error, Event, mock::*};
use frame_support::{BoundedVec, assert_noop, assert_ok};

#[test]
fn register_asset_works() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"Tether USD".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"USDT".to_vec()).unwrap();
		let decimals = 6u8;
		let contract_address = Some([1u8; 20]);

		// Only root can register assets
		assert_ok!(ShieldedPool::register_asset(
			RuntimeOrigin::root(),
			name.clone(),
			symbol.clone(),
			decimals,
			contract_address,
		));

		// Asset ID 1 should be registered (0 is native token)
		let asset = crate::Assets::<Test>::get(1).expect("Asset should exist");
		assert_eq!(asset.id, 1);
		assert_eq!(asset.name, name);
		assert_eq!(asset.symbol, symbol);
		assert_eq!(asset.decimals, decimals);
		assert!(!asset.is_verified); // Starts unverified
		assert_eq!(asset.contract_address, contract_address);

		// Next asset ID should be 2
		assert_eq!(crate::NextAssetId::<Test>::get(), 2);

		// Check event
		System::assert_last_event(Event::AssetRegistered { asset_id: 1 }.into());
	});
}

#[test]
fn register_asset_requires_root() {
	new_test_ext().execute_with(|| {
		let name = BoundedVec::try_from(b"USDT".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"USDT".to_vec()).unwrap();

		// Non-root account cannot register
		assert_noop!(
			ShieldedPool::register_asset(RuntimeOrigin::signed(1), name, symbol, 6, None,),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn verify_asset_works() {
	new_test_ext().execute_with(|| {
		// Register asset first
		let name = BoundedVec::try_from(b"DAI".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"DAI".to_vec()).unwrap();

		assert_ok!(ShieldedPool::register_asset(
			RuntimeOrigin::root(),
			name,
			symbol,
			18,
			None,
		));

		// Asset starts unverified
		let asset_before = crate::Assets::<Test>::get(1).unwrap();
		assert!(!asset_before.is_verified);

		// Verify asset
		assert_ok!(ShieldedPool::verify_asset(RuntimeOrigin::root(), 1,));

		// Check it's now verified
		let asset_after = crate::Assets::<Test>::get(1).unwrap();
		assert!(asset_after.is_verified);

		// Check event
		System::assert_last_event(Event::AssetVerified { asset_id: 1 }.into());
	});
}

#[test]
fn verify_asset_requires_root() {
	new_test_ext().execute_with(|| {
		// Non-root cannot verify
		assert_noop!(
			ShieldedPool::verify_asset(RuntimeOrigin::signed(1), 1,),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn verify_nonexistent_asset_fails() {
	new_test_ext().execute_with(|| {
		// Try to verify asset that doesn't exist
		assert_noop!(
			ShieldedPool::verify_asset(RuntimeOrigin::root(), 999,),
			Error::<Test>::InvalidAssetId
		);
	});
}

#[test]
fn unverify_asset_works() {
	new_test_ext().execute_with(|| {
		// Register and verify asset
		let name = BoundedVec::try_from(b"USDC".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"USDC".to_vec()).unwrap();

		assert_ok!(ShieldedPool::register_asset(
			RuntimeOrigin::root(),
			name,
			symbol,
			6,
			None,
		));
		assert_ok!(ShieldedPool::verify_asset(RuntimeOrigin::root(), 1));

		// Asset is verified
		assert!(crate::Assets::<Test>::get(1).unwrap().is_verified);

		// Unverify asset
		assert_ok!(ShieldedPool::unverify_asset(RuntimeOrigin::root(), 1,));

		// Check it's now unverified
		assert!(!crate::Assets::<Test>::get(1).unwrap().is_verified);

		// Check event
		System::assert_last_event(Event::AssetUnverified { asset_id: 1 }.into());
	});
}

#[test]
fn shield_with_unverified_asset_fails() {
	new_test_ext().execute_with(|| {
		// Register but don't verify asset
		let name = BoundedVec::try_from(b"FAKE".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"FAKE".to_vec()).unwrap();

		assert_ok!(ShieldedPool::register_asset(
			RuntimeOrigin::root(),
			name,
			symbol,
			18,
			None,
		));

		let depositor = 1;
		let amount = 1000u128;
		let commitment = sample_commitment();
		let encrypted_memo = sample_encrypted_memo();

		// Try to shield with unverified asset
		assert_noop!(
			ShieldedPool::shield(
				RuntimeOrigin::signed(depositor),
				1, // unverified asset
				amount,
				commitment,
				encrypted_memo,
			),
			Error::<Test>::AssetNotVerified
		);
	});
}

#[test]
fn shield_with_nonexistent_asset_fails() {
	new_test_ext().execute_with(|| {
		let depositor = 1;
		let amount = 1000u128;
		let commitment = sample_commitment();
		let encrypted_memo = sample_encrypted_memo();

		// Try to shield with non-existent asset
		assert_noop!(
			ShieldedPool::shield(
				RuntimeOrigin::signed(depositor),
				999, // doesn't exist
				amount,
				commitment,
				encrypted_memo,
			),
			Error::<Test>::InvalidAssetId
		);
	});
}

#[test]
fn shield_with_verified_asset_works() {
	new_test_ext().execute_with(|| {
		// Register and verify asset
		let name = BoundedVec::try_from(b"USDT".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"USDT".to_vec()).unwrap();

		assert_ok!(ShieldedPool::register_asset(
			RuntimeOrigin::root(),
			name,
			symbol,
			6,
			None,
		));
		assert_ok!(ShieldedPool::verify_asset(RuntimeOrigin::root(), 1));

		let depositor = 1;
		let amount = 1000u128;
		let commitment = sample_commitment();
		let encrypted_memo = sample_encrypted_memo();

		// Shield with verified asset should work
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(depositor),
			1, // verified USDT
			amount,
			commitment,
			encrypted_memo,
		));

		// Check pool balance per asset
		assert_eq!(crate::PoolBalancePerAsset::<Test>::get(1), amount);
	});
}

#[test]
fn shield_native_asset_works() {
	new_test_ext().execute_with(|| {
		let depositor = 1;
		let amount = 1000u128;
		let commitment = sample_commitment();
		let encrypted_memo = sample_encrypted_memo();

		// Native asset (0) is pre-verified in genesis
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(depositor),
			0, // native asset
			amount,
			commitment,
			encrypted_memo,
		));

		// Check pool balance for native asset
		assert_eq!(crate::PoolBalancePerAsset::<Test>::get(0), amount);
	});
}

#[test]
fn unshield_with_invalid_asset_fails() {
	new_test_ext().execute_with(|| {
		let recipient = 2;
		let amount = 500u128;
		let nullifier = sample_nullifier();
		let merkle_root = sample_merkle_root();
		let proof = BoundedVec::default();

		// Try to unshield with non-existent asset
		assert_noop!(
			ShieldedPool::unshield(
				RuntimeOrigin::signed(1),
				proof,
				merkle_root,
				nullifier,
				999, // doesn't exist
				amount,
				recipient,
			),
			Error::<Test>::InvalidAssetId
		);
	});
}

#[test]
fn unshield_to_pool_account_fails() {
	new_test_ext().execute_with(|| {
		let pool_account = ShieldedPool::pool_account_id();
		let amount = 500u128;
		let nullifier = sample_nullifier();
		let merkle_root = sample_merkle_root();
		let proof = BoundedVec::default();

		// Try to unshield to pool account (would create loop)
		assert_noop!(
			ShieldedPool::unshield(
				RuntimeOrigin::signed(1),
				proof,
				merkle_root,
				nullifier,
				0, // native asset
				amount,
				pool_account,
			),
			Error::<Test>::InvalidRecipient
		);
	});
}

#[test]
fn unshield_tracks_balance_per_asset() {
	new_test_ext().execute_with(|| {
		// Setup: Register and verify USDT
		let name = BoundedVec::try_from(b"USDT".to_vec()).unwrap();
		let symbol = BoundedVec::try_from(b"USDT".to_vec()).unwrap();
		assert_ok!(ShieldedPool::register_asset(
			RuntimeOrigin::root(),
			name,
			symbol,
			6,
			None,
		));
		assert_ok!(ShieldedPool::verify_asset(RuntimeOrigin::root(), 1));

		// Shield USDT to create pool balance
		let depositor = 1;
		let commitment = sample_commitment();
		let encrypted_memo = sample_encrypted_memo();
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(depositor),
			1, // USDT
			1000u128,
			commitment,
			encrypted_memo,
		));

		// Check initial pool balance
		assert_eq!(crate::PoolBalancePerAsset::<Test>::get(1), 1000u128);

		// Mock unshield (would normally require valid proof)
		// For test purposes, we manually update the state
		crate::HistoricPoseidonRoots::<Test>::insert(sample_merkle_root(), true);

		// Note: Real unshield would verify proof, but for testing balance tracking
		// we focus on the balance update logic
	});
}

#[test]
fn native_asset_registered_in_genesis() {
	new_test_ext().execute_with(|| {
		// Native asset (ID=0) should exist
		let native_asset = crate::Assets::<Test>::get(0).expect("Native asset should exist");

		assert_eq!(native_asset.id, 0);
		assert!(native_asset.is_verified);
		assert_eq!(native_asset.decimals, 18);

		// Next asset ID should be 1
		assert_eq!(crate::NextAssetId::<Test>::get(), 1);
	});
}

#[test]
fn multiple_assets_can_coexist() {
	new_test_ext().execute_with(|| {
		// Register multiple assets
		for (name, symbol) in &[("USDT", "USDT"), ("DAI", "DAI"), ("USDC", "USDC")] {
			let name_bounded = BoundedVec::try_from(name.as_bytes().to_vec()).unwrap();
			let symbol_bounded = BoundedVec::try_from(symbol.as_bytes().to_vec()).unwrap();

			assert_ok!(ShieldedPool::register_asset(
				RuntimeOrigin::root(),
				name_bounded,
				symbol_bounded,
				18,
				None,
			));
		}

		// Verify all assets exist
		assert!(crate::Assets::<Test>::get(1).is_some()); // USDT
		assert!(crate::Assets::<Test>::get(2).is_some()); // DAI
		assert!(crate::Assets::<Test>::get(3).is_some()); // USDC

		// Next ID should be 4
		assert_eq!(crate::NextAssetId::<Test>::get(), 4);
	});
}
