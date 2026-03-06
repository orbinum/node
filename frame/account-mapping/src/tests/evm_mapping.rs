use crate::mock::{new_test_ext, AccountMapping, RuntimeOrigin, Test};
use crate::Error;
use frame_support::{assert_noop, assert_ok};
use sp_core::H160;

#[test]
fn native_account_cannot_be_mapped() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AccountMapping::map_account(RuntimeOrigin::signed(42)),
			Error::<Test>::NativeAccountCannotBeMapped
		);
	});
}

#[test]
fn map_account_stores_bidirectional_mapping() {
	new_test_ext().execute_with(|| {
		assert_ok!(AccountMapping::map_account(RuntimeOrigin::signed(1)));

		let address = H160::from_low_u64_be(1);
		assert_eq!(AccountMapping::mapped_account(address), Some(1));
		assert_eq!(AccountMapping::mapped_address(1), Some(address));
	});
}

#[test]
fn map_account_fails_if_account_already_mapped() {
	new_test_ext().execute_with(|| {
		assert_ok!(AccountMapping::map_account(RuntimeOrigin::signed(2)));
		assert_noop!(
			AccountMapping::map_account(RuntimeOrigin::signed(2)),
			Error::<Test>::AlreadyMapped
		);
	});
}

#[test]
fn map_account_fails_if_address_already_mapped() {
	new_test_ext().execute_with(|| {
		assert_ok!(AccountMapping::map_account(RuntimeOrigin::signed(1)));
		assert_noop!(
			AccountMapping::map_account(RuntimeOrigin::signed(3)),
			Error::<Test>::AddressAlreadyMapped
		);
	});
}

#[test]
fn unmap_account_removes_bidirectional_mapping() {
	new_test_ext().execute_with(|| {
		assert_ok!(AccountMapping::map_account(RuntimeOrigin::signed(2)));

		let address = H160::from_low_u64_be(0);
		assert_eq!(AccountMapping::mapped_account(address), Some(2));

		assert_ok!(AccountMapping::unmap_account(RuntimeOrigin::signed(2)));

		assert_eq!(AccountMapping::mapped_account(address), None);
		assert_eq!(AccountMapping::mapped_address(2), None);
	});
}

#[test]
fn unmap_account_fails_if_not_mapped() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AccountMapping::unmap_account(RuntimeOrigin::signed(42)),
			Error::<Test>::NotMapped
		);
	});
}

#[test]
fn account_can_remap_after_unmap() {
	new_test_ext().execute_with(|| {
		assert_ok!(AccountMapping::map_account(RuntimeOrigin::signed(1)));
		assert_ok!(AccountMapping::unmap_account(RuntimeOrigin::signed(1)));
		assert_ok!(AccountMapping::map_account(RuntimeOrigin::signed(1)));

		let address = H160::from_low_u64_be(1);
		assert_eq!(AccountMapping::mapped_account(address), Some(1));
		assert_eq!(AccountMapping::mapped_address(1), Some(address));
	});
}
