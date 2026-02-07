//! Tests for asset_metadata

use crate::domain::entities::AssetMetadata;
use frame_support::BoundedVec;

type AccountId = u64;
type BlockNumber = u64;

#[test]
fn new_asset_is_unverified() {
	let name = BoundedVec::try_from(b"Test Asset".to_vec()).unwrap();
	let symbol = BoundedVec::try_from(b"TEST".to_vec()).unwrap();
	let asset = AssetMetadata::<AccountId, BlockNumber>::new(1, name, symbol, 18, 100, 1);

	assert!(!asset.is_verified());
}

#[test]
fn can_verify_asset() {
	let name = BoundedVec::try_from(b"Test Asset".to_vec()).unwrap();
	let symbol = BoundedVec::try_from(b"TEST".to_vec()).unwrap();
	let mut asset = AssetMetadata::<AccountId, BlockNumber>::new(1, name, symbol, 18, 100, 1);

	asset.verify();
	assert!(asset.is_verified());
}

#[test]
fn can_set_contract_address() {
	let name = BoundedVec::try_from(b"Test Asset".to_vec()).unwrap();
	let symbol = BoundedVec::try_from(b"TEST".to_vec()).unwrap();
	let mut asset = AssetMetadata::<AccountId, BlockNumber>::new(1, name, symbol, 18, 100, 1);

	let address = [1u8; 20];
	asset.set_contract_address(address);
	assert_eq!(asset.contract_address, Some(address));
}
