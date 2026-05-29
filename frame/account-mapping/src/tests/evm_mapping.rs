use crate::mock::{new_test_ext, AccountMapping, RuntimeOrigin, Test};
use crate::{Error, MappedAccounts, OriginalAccounts};
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

// ── Phase 1 alignment: implicit secp256k1 accounts (account 100 in mock) ────

/// map_account for an implicit secp256k1 account must NOT write to storage.
/// The mapping is always derivable from the AccountId — storage is redundant.
#[test]
fn map_account_secp256k1_does_not_write_storage() {
	new_test_ext().execute_with(|| {
		assert_ok!(AccountMapping::map_account(RuntimeOrigin::signed(100)));

		// No storage entry written — mapping is implicit.
		assert!(!OriginalAccounts::<Test>::contains_key(100));
		assert_eq!(AccountMapping::mapped_address(100), None);

		// Calling again is idempotent (no AlreadyMapped error).
		assert_ok!(AccountMapping::map_account(RuntimeOrigin::signed(100)));
	});
}

/// unmap_account for an implicit secp256k1 account with no prior map_account
/// must succeed (emit event) without returning NotMapped.
#[test]
fn unmap_account_secp256k1_without_storage_entry_succeeds() {
	new_test_ext().execute_with(|| {
		// Never called map_account — no storage entry exists.
		assert_ok!(AccountMapping::unmap_account(RuntimeOrigin::signed(100)));

		// Storage remains empty.
		assert!(!OriginalAccounts::<Test>::contains_key(100));
	});
}

/// unmap_account for an implicit secp256k1 account that has a legacy storage
/// entry (written before Phase 3) must clean up the entry.
#[test]
fn unmap_account_secp256k1_cleans_up_legacy_storage_entry() {
	new_test_ext().execute_with(|| {
		// Simulate a legacy entry written directly (as if from before Phase 3).
		let address = H160::from_low_u64_be(0); // TestEvmAddress::convert(100) = H160::from_low_u64_be(0)
		OriginalAccounts::<Test>::insert(100u64, address);
		MappedAccounts::<Test>::insert(address, 100u64);

		assert_ok!(AccountMapping::unmap_account(RuntimeOrigin::signed(100)));

		// Legacy entries removed.
		assert!(!OriginalAccounts::<Test>::contains_key(100u64));
		assert_eq!(MappedAccounts::<Test>::get(address), None);
	});
}
