use crate::mock::{new_test_ext, AccountMapping, RuntimeOrigin, Test};
use crate::{Error, SignatureScheme};
use frame_support::{assert_noop, assert_ok};

use super::make_commitment;

#[test]
fn register_private_link_requires_alias() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AccountMapping::register_private_link(RuntimeOrigin::signed(1), 1u32, [0xAAu8; 32]),
			Error::<Test>::NoAlias
		);
	});
}

#[test]
fn register_private_link_happy_path() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let commitment = make_commitment(501, b"solana_address_here_32_bytes____", &[0x11u8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			commitment
		));

		let stored = AccountMapping::private_chain_links(alias);
		assert_eq!(stored.len(), 1);
		assert_eq!(stored[0].chain_id, 501u32);
		assert_eq!(stored[0].commitment, commitment);
	});
}

#[test]
fn register_private_link_rejects_duplicate_commitment() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let commitment = make_commitment(501, b"addr", &[0x22u8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			commitment
		));
		assert_noop!(
			AccountMapping::register_private_link(RuntimeOrigin::signed(1), 501u32, commitment),
			Error::<Test>::PrivateLinkAlreadyExists
		);
	});
}

#[test]
fn register_private_link_rejects_duplicate_chain_id() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let c1 = make_commitment(501, b"addr_one", &[0x33u8; 32]);
		let c2 = make_commitment(501, b"addr_two", &[0x44u8; 32]); // mismo chain_id, distinto commitment
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			c1
		));
		assert_noop!(
			AccountMapping::register_private_link(RuntimeOrigin::signed(1), 501u32, c2),
			Error::<Test>::PrivateLinkAlreadyExists
		);
	});
}

#[test]
fn multiple_private_links_can_coexist() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let c_sol = make_commitment(501, b"sol_addr", &[0x01u8; 32]);
		let c_btc = make_commitment(60, b"btc_addr", &[0x02u8; 32]);
		let c_eth = make_commitment(1, b"eth_addr", &[0x03u8; 32]);

		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			c_sol
		));
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			60u32,
			c_btc
		));
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			1u32,
			c_eth
		));

		assert_eq!(AccountMapping::private_chain_links(alias).len(), 3);
	});
}

#[test]
fn remove_private_link_happy_path() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let commitment = make_commitment(501, b"addr", &[0x55u8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			commitment
		));
		assert_eq!(AccountMapping::private_chain_links(alias.clone()).len(), 1);

		assert_ok!(AccountMapping::remove_private_link(
			RuntimeOrigin::signed(1),
			commitment
		));
		assert_eq!(AccountMapping::private_chain_links(alias).len(), 0);
	});
}

#[test]
fn remove_private_link_fails_if_not_found() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		assert_noop!(
			AccountMapping::remove_private_link(RuntimeOrigin::signed(1), [0xFFu8; 32]),
			Error::<Test>::PrivateLinkNotFound
		);
	});
}

#[test]
fn release_alias_clears_private_links() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let c1 = make_commitment(501, b"sol_addr", &[0xAAu8; 32]);
		let c2 = make_commitment(60, b"btc_addr", &[0xBBu8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			c1
		));
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			60u32,
			c2
		));
		assert_eq!(AccountMapping::private_chain_links(alias.clone()).len(), 2);

		assert_ok!(AccountMapping::release_alias(RuntimeOrigin::signed(1)));
		assert_eq!(AccountMapping::private_chain_links(alias).len(), 0);
	});
}

#[test]
fn reveal_private_link_fails_if_commitment_not_found() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		assert_noop!(
			AccountMapping::reveal_private_link(
				RuntimeOrigin::signed(1),
				[0xFFu8; 32],
				b"some_addr".to_vec(),
				[0x00u8; 32],
				vec![0u8; 65],
			),
			Error::<Test>::PrivateLinkNotFound
		);
	});
}

#[test]
fn reveal_private_link_fails_on_commitment_mismatch() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let addr = b"some_eth_address____";
		let blinding = [0xBEu8; 32];
		let real_commitment = make_commitment(1, addr, &blinding);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			1u32,
			real_commitment
		));

		assert_noop!(
			AccountMapping::reveal_private_link(
				RuntimeOrigin::signed(1),
				real_commitment,
				addr.to_vec(),
				[0xDEu8; 32],
				vec![0u8; 65],
			),
			Error::<Test>::CommitmentMismatch
		);
	});
}

#[test]
fn reveal_private_link_fails_after_correct_commitment_if_chain_unsupported() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let addr = b"some_eth_address____";
		let blinding = [0xCAu8; 32];
		let chain_id = 9999u32;
		let commitment = make_commitment(chain_id, addr, &blinding);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			chain_id,
			commitment
		));

		assert_noop!(
			AccountMapping::reveal_private_link(
				RuntimeOrigin::signed(1),
				commitment,
				addr.to_vec(),
				blinding,
				vec![0u8; 65],
			),
			Error::<Test>::UnsupportedChain
		);
	});
}

#[test]
fn reveal_private_link_fails_with_invalid_signature_for_supported_chain() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		assert_ok!(AccountMapping::add_supported_chain(
			RuntimeOrigin::root(),
			1u32,
			SignatureScheme::Eip191,
		));

		let addr = b"some_eth_address____";
		let blinding = [0xFAu8; 32];
		let commitment = make_commitment(1, addr, &blinding);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			1u32,
			commitment
		));

		assert_noop!(
			AccountMapping::reveal_private_link(
				RuntimeOrigin::signed(1),
				commitment,
				addr.to_vec(),
				blinding,
				vec![0u8; 65],
			),
			Error::<Test>::InvalidSignature
		);
	});
}

#[test]
fn private_and_public_links_coexist_on_same_alias() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let c = make_commitment(501, b"sol_addr", &[0x01u8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			c
		));

		let record = AccountMapping::identity_of(alias.clone()).unwrap();
		assert_eq!(record.chain_links.len(), 0);
		assert_eq!(AccountMapping::private_chain_links(alias).len(), 1);
	});
}
