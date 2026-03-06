use crate::mock::{new_test_ext, AccountMapping, Balances, RuntimeOrigin, Test};
use crate::Error;
use frame_support::{assert_noop, assert_ok};

#[test]
fn buy_alias_full_flow() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"buyable".to_vec().try_into().unwrap();

		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));
		assert_ok!(AccountMapping::put_alias_on_sale(
			RuntimeOrigin::signed(1),
			200_u64,
			None
		));

		let seller_free_before = Balances::free_balance(1);
		let buyer_free_before = Balances::free_balance(2);

		assert_ok!(AccountMapping::buy_alias(
			RuntimeOrigin::signed(2),
			alias.clone()
		));
		assert_eq!(AccountMapping::alias_of(2), Some(alias.clone()));
		assert!(AccountMapping::alias_of(1).is_none());
		assert_eq!(Balances::free_balance(1), seller_free_before + 200 + 100);
		assert_eq!(Balances::reserved_balance(2), 100);
		assert_eq!(Balances::free_balance(2), buyer_free_before - 200 - 100);
		assert!(AccountMapping::listing_price(alias).is_none());
	});
}

#[test]
fn release_alias_clears_active_listing() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"forsale".to_vec().try_into().unwrap();

		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));
		assert_ok!(AccountMapping::put_alias_on_sale(
			RuntimeOrigin::signed(1),
			500_u64,
			None
		));
		assert!(AccountMapping::listing_price(alias.clone()).is_some());

		assert_ok!(AccountMapping::release_alias(RuntimeOrigin::signed(1)));

		assert!(
			AccountMapping::listing_price(alias).is_none(),
			"[C-1] El listing no fue eliminado al liberar el alias"
		);
	});
}

#[test]
fn transfer_alias_clears_active_listing() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"txfrsale".to_vec().try_into().unwrap();

		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));
		assert_ok!(AccountMapping::put_alias_on_sale(
			RuntimeOrigin::signed(1),
			500_u64,
			None
		));
		assert!(AccountMapping::listing_price(alias.clone()).is_some());

		assert_ok!(AccountMapping::transfer_alias(RuntimeOrigin::signed(1), 2));

		assert!(
			AccountMapping::listing_price(alias).is_none(),
			"[C-2] El listing fue heredado por el nuevo propietario sin su consentimiento"
		);
	});
}

#[test]
fn set_account_metadata_requires_alias() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AccountMapping::set_account_metadata(RuntimeOrigin::signed(3), None, None, None),
			Error::<Test>::NoAlias
		);
	});
}
