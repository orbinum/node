//! Tests for asset_id

use crate::domain::value_objects::AssetId;

#[test]
fn native_asset_works() {
	let native = AssetId::native();
	assert_eq!(native.0, 0);
	assert!(native.is_native());
}

#[test]
fn non_native_asset_works() {
	let usdt = AssetId::new(1);
	assert_eq!(usdt.0, 1);
	assert!(!usdt.is_native());
}

#[test]
fn asset_id_display_works() {
	let native = AssetId::native();
	assert_eq!(format!("{native}"), "Native Asset (0)");

	let asset = AssetId::new(42);
	assert_eq!(format!("{asset}"), "Asset 42");
}

#[test]
fn asset_id_ordering_works() {
	let a1 = AssetId::new(1);
	let a2 = AssetId::new(2);
	let a3 = AssetId::new(1);

	assert!(a1 < a2);
	assert_eq!(a1, a3);
}
