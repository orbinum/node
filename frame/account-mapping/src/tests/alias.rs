use crate::mock::{new_test_ext, AccountMapping, Balances, RuntimeOrigin, Test};
use crate::Error;
use frame_support::{assert_noop, assert_ok};

#[test]
fn register_alias_succeeds_and_reserves_deposit() {
	new_test_ext().execute_with(|| {
		let alias = b"nolasco".to_vec().try_into().unwrap();
		let before = Balances::free_balance(1);

		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		assert_eq!(Balances::reserved_balance(1), 100);
		assert_eq!(Balances::free_balance(1), before - 100);
	});
}

#[test]
fn register_alias_creates_bidirectional_index() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"nolasco".to_vec().try_into().unwrap();

		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let record = AccountMapping::identity_of(alias.clone()).expect("identity must exist");
		assert_eq!(record.owner, 1);

		let stored_alias = AccountMapping::alias_of(1).expect("alias index must exist");
		assert_eq!(stored_alias, alias);
	});
}

#[test]
fn register_alias_fails_if_already_has_alias() {
	new_test_ext().execute_with(|| {
		let alias1 = b"first".to_vec().try_into().unwrap();
		let alias2 = b"second".to_vec().try_into().unwrap();

		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias1
		));
		assert_noop!(
			AccountMapping::register_alias(RuntimeOrigin::signed(1), alias2),
			Error::<Test>::AlreadyHasAlias
		);
	});
}

#[test]
fn register_alias_fails_if_alias_taken() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"taken".to_vec().try_into().unwrap();

		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));
		assert_noop!(
			AccountMapping::register_alias(RuntimeOrigin::signed(2), alias),
			Error::<Test>::AliasTaken
		);
	});
}

#[test]
fn register_alias_rejects_invalid_characters() {
	new_test_ext().execute_with(|| {
		let bad: crate::pallet::AliasOf<Test> = b"Bad@Alias!".to_vec().try_into().unwrap();
		assert_noop!(
			AccountMapping::register_alias(RuntimeOrigin::signed(1), bad),
			Error::<Test>::InvalidAliasCharacters
		);
	});
}

#[test]
fn register_alias_rejects_too_short_alias() {
	new_test_ext().execute_with(|| {
		let short: crate::pallet::AliasOf<Test> = b"ab".to_vec().try_into().unwrap();
		assert_noop!(
			AccountMapping::register_alias(RuntimeOrigin::signed(1), short),
			Error::<Test>::AliasTooShort
		);
	});
}

#[test]
fn release_alias_unreserves_deposit_and_clears_index() {
	new_test_ext().execute_with(|| {
		let alias = b"nolasco".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		let before_release = Balances::free_balance(1);
		assert_ok!(AccountMapping::release_alias(RuntimeOrigin::signed(1)));

		assert_eq!(Balances::free_balance(1), before_release + 100);
		assert_eq!(Balances::reserved_balance(1), 0);
		assert!(AccountMapping::alias_of(1).is_none());
	});
}

#[test]
fn release_alias_fails_if_no_alias() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AccountMapping::release_alias(RuntimeOrigin::signed(42)),
			Error::<Test>::NoAlias
		);
	});
}

#[test]
fn resolve_alias_returns_identity_record() {
	new_test_ext().execute_with(|| {
		let alias = b"queried".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(2),
			alias
		));

		let record = crate::Pallet::<Test>::resolve_alias(b"queried").unwrap();
		assert_eq!(record.owner, 2);
		assert!(record.chain_links.is_empty());
	});
}

#[test]
fn transfer_alias_moves_ownership_and_deposit() {
	new_test_ext().execute_with(|| {
		let alias = b"xfer_ok".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		let deposit_before_2 = Balances::reserved_balance(2);

		assert_ok!(AccountMapping::transfer_alias(RuntimeOrigin::signed(1), 2));

		assert!(AccountMapping::alias_of(1).is_none());
		assert_eq!(Balances::reserved_balance(1), 0);

		let alias2 = AccountMapping::alias_of(2).expect("account 2 must now own the alias");
		assert_eq!(&alias2[..], b"xfer_ok");
		assert_eq!(Balances::reserved_balance(2), deposit_before_2 + 100);

		let record = AccountMapping::identity_of(alias2).expect("identity must exist");
		assert_eq!(record.owner, 2);
	});
}

#[test]
fn transfer_alias_fails_if_caller_has_no_alias() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AccountMapping::transfer_alias(RuntimeOrigin::signed(42), 1),
			Error::<Test>::NoAlias
		);
	});
}

#[test]
fn transfer_alias_fails_if_destination_already_has_alias() {
	new_test_ext().execute_with(|| {
		let a1: crate::pallet::AliasOf<Test> = b"sender".to_vec().try_into().unwrap();
		let a2: crate::pallet::AliasOf<Test> = b"recvr".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(RuntimeOrigin::signed(1), a1));
		assert_ok!(AccountMapping::register_alias(RuntimeOrigin::signed(2), a2));

		assert_noop!(
			AccountMapping::transfer_alias(RuntimeOrigin::signed(1), 2),
			Error::<Test>::NewOwnerAlreadyHasAlias
		);
	});
}

#[test]
fn transfer_alias_fails_if_self_transfer() {
	new_test_ext().execute_with(|| {
		let alias = b"selfxfr".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		assert_noop!(
			AccountMapping::transfer_alias(RuntimeOrigin::signed(1), 1),
			Error::<Test>::CannotTransferToSelf
		);
	});
}

#[test]
fn set_account_metadata_succeeds() {
	new_test_ext().execute_with(|| {
		let alias = b"nolasco".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		let name = Some(b"Nolasco".to_vec().try_into().unwrap());
		let bio = Some(b"Dev at Orbinum".to_vec().try_into().unwrap());

		assert_ok!(AccountMapping::set_account_metadata(
			RuntimeOrigin::signed(1),
			name.clone(),
			bio.clone(),
			None,
		));

		let meta = AccountMapping::account_metadata(1).unwrap();
		assert_eq!(meta.display_name, name);
		assert_eq!(meta.bio, bio);
		assert_eq!(meta.avatar, None);
	});
}
