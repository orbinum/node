//! Genesis: the native asset, the initial root and the historic-root window.

use crate::{
	pallet::{Assets, HistoricPoseidonRoots, NextAssetId, PoseidonRoot},
	tests::mock::{Test, new_test_ext},
};

#[test]
fn genesis_next_asset_id_is_one() {
	new_test_ext().execute_with(|| {
		assert_eq!(NextAssetId::<Test>::get(), 1);
	});
}

#[test]
fn genesis_native_asset_registered_and_verified() {
	new_test_ext().execute_with(|| {
		let asset = Assets::<Test>::get(0).expect("Native asset (ORB) must exist after genesis");
		assert_eq!(asset.id, 0);
		assert!(asset.is_verified, "Native asset must be verified");
		assert_eq!(asset.symbol.as_slice(), b"ORB");
		assert_eq!(asset.decimals, 18);
		assert_eq!(asset.contract_address, None);
	});
}

#[test]
fn genesis_root_added_to_historic_roots() {
	new_test_ext().execute_with(|| {
		let root = PoseidonRoot::<Test>::get();
		assert!(
			HistoricPoseidonRoots::<Test>::get(root).is_some(),
			"Genesis root must be in historic roots"
		);
	});
}

#[test]
fn initialize_genesis_sets_custom_root() {
	new_test_ext().execute_with(|| {
		let custom_root = [0xABu8; 32];
		crate::genesis::initialize_genesis::<Test>(custom_root);
		assert_eq!(PoseidonRoot::<Test>::get(), custom_root);
	});
}

#[test]
fn initialize_genesis_registers_custom_root_in_historic() {
	new_test_ext().execute_with(|| {
		let custom_root = [0xCDu8; 32];
		crate::genesis::initialize_genesis::<Test>(custom_root);
		assert!(
			HistoricPoseidonRoots::<Test>::get(custom_root).is_some(),
			"Custom root must be in historic roots"
		);
	});
}

#[test]
fn initialize_genesis_resets_next_asset_id_to_one() {
	new_test_ext().execute_with(|| {
		crate::genesis::initialize_genesis::<Test>([0xEFu8; 32]);
		// After re-initializing, NextAssetId should be 1 (native asset inserted at 0)
		assert_eq!(NextAssetId::<Test>::get(), 1);
	});
}
