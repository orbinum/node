use crate::mock::{new_test_ext, AccountMapping, RuntimeCall, RuntimeEvent, RuntimeOrigin, Test};
use crate::Error;
use frame_support::{assert_noop, assert_ok};

use super::make_commitment;

fn valid_proof() -> alloc::vec::Vec<u8> {
	let mut v = alloc::vec![0u8; 64];
	v[0] = 0x01;
	v
}

fn invalid_proof() -> alloc::vec::Vec<u8> {
	alloc::vec![0x00u8; 64]
}

fn remark_call() -> alloc::boxed::Box<RuntimeCall> {
	alloc::boxed::Box::new(RuntimeCall::System(frame_system::Call::remark {
		remark: alloc::vec![],
	}))
}

#[test]
fn dispatch_as_private_link_requires_alias() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			AccountMapping::dispatch_as_private_link(
				RuntimeOrigin::signed(99),
				1u64,
				[0xAAu8; 32],
				valid_proof(),
				remark_call(),
			),
			Error::<Test>::NoAlias
		);
	});
}

#[test]
fn dispatch_as_private_link_fails_if_commitment_not_registered() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		assert_noop!(
			AccountMapping::dispatch_as_private_link(
				RuntimeOrigin::signed(99),
				1u64,
				[0xBBu8; 32],
				valid_proof(),
				remark_call(),
			),
			Error::<Test>::PrivateLinkNotFound
		);
	});
}

#[test]
fn dispatch_as_private_link_rejects_invalid_proof() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		let commitment = make_commitment(501, b"sol_addr", &[0x01u8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			commitment
		));

		assert_noop!(
			AccountMapping::dispatch_as_private_link(
				RuntimeOrigin::signed(99),
				1u64,
				commitment,
				invalid_proof(),
				remark_call(),
			),
			Error::<Test>::InvalidProof
		);
	});
}

#[test]
fn dispatch_as_private_link_executes_call_with_valid_proof() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let commitment = make_commitment(501, b"sol_addr", &[0x01u8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			commitment
		));

		assert_ok!(AccountMapping::dispatch_as_private_link(
			RuntimeOrigin::signed(99),
			1u64,
			commitment,
			valid_proof(),
			remark_call(),
		));

		assert_eq!(AccountMapping::private_chain_links(alias).len(), 1);
	});
}

#[test]
fn dispatch_as_private_link_emits_event() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let commitment = make_commitment(501, b"sol_addr", &[0x01u8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			commitment
		));

		assert_ok!(AccountMapping::dispatch_as_private_link(
			RuntimeOrigin::signed(99),
			1u64,
			commitment,
			valid_proof(),
			remark_call(),
		));

		let events = frame_system::Pallet::<Test>::events();
		let found = events.iter().any(|e| {
			matches!(
				&e.event,
				RuntimeEvent::AccountMapping(crate::Event::PrivateLinkDispatchExecuted { owner, commitment: c })
				if *owner == 1u64 && *c == commitment
			)
		});
		assert!(found, "PrivateLinkDispatchExecuted event not emitted");
	});
}

#[test]
fn dispatch_as_private_link_can_be_called_by_relayer() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let commitment = make_commitment(501, b"sol_addr", &[0x77u8; 32]);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			commitment
		));

		assert_ok!(AccountMapping::dispatch_as_private_link(
			RuntimeOrigin::signed(3),
			1u64,
			commitment,
			valid_proof(),
			remark_call(),
		));
	});
}

#[test]
fn dispatch_as_private_link_does_not_reveal_address() {
	new_test_ext().execute_with(|| {
		let alias: crate::pallet::AliasOf<Test> = b"alice".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias.clone()
		));

		let addr = b"sol_secret_address__";
		let blinding = [0x42u8; 32];
		let commitment = make_commitment(501, addr, &blinding);
		assert_ok!(AccountMapping::register_private_link(
			RuntimeOrigin::signed(1),
			501u32,
			commitment
		));

		assert_ok!(AccountMapping::dispatch_as_private_link(
			RuntimeOrigin::signed(99),
			1u64,
			commitment,
			valid_proof(),
			remark_call(),
		));

		let bounded_addr: crate::ExternalAddr = addr.to_vec().try_into().unwrap();
		assert!(
			AccountMapping::link_owner((501u32, bounded_addr)).is_none(),
			"Address was leaked into public ReverseChainLinks"
		);

		let links = AccountMapping::private_chain_links(alias);
		assert_eq!(links.len(), 1);
		assert_eq!(links[0].commitment, commitment);
	});
}

extern crate alloc;
