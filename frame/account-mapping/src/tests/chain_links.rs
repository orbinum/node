use crate::mock::{new_test_ext, AccountMapping, RuntimeCall, RuntimeOrigin, Test};
use crate::{Error, SignatureScheme};
use frame_support::{assert_noop, assert_ok};

#[test]
fn remove_chain_link_succeeds() {
	new_test_ext().execute_with(|| {
		let alias_key: crate::pallet::AliasOf<Test> = b"multichain".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias_key.clone()
		));

		let mut record = crate::Identities::<Test>::get(&alias_key).unwrap();
		record
			.chain_links
			.try_push(crate::ChainLink {
				chain_id: 1,
				address: b"0x123".to_vec().try_into().unwrap(),
			})
			.unwrap();
		crate::Identities::<Test>::insert(&alias_key, record);

		assert_ok!(AccountMapping::remove_chain_link(
			RuntimeOrigin::signed(1),
			1
		));

		let record_after = crate::Identities::<Test>::get(&alias_key).unwrap();
		assert!(record_after.chain_links.is_empty());
	});
}

#[test]
fn governance_can_add_and_remove_supported_chains() {
	new_test_ext().execute_with(|| {
		assert_ok!(AccountMapping::add_supported_chain(
			RuntimeOrigin::root(),
			123,
			SignatureScheme::Ed25519,
		));
		assert_eq!(
			AccountMapping::supported_chain(123),
			Some(SignatureScheme::Ed25519)
		);

		assert_ok!(AccountMapping::remove_supported_chain(
			RuntimeOrigin::root(),
			123
		));
		assert_eq!(AccountMapping::supported_chain(123), None);
	});
}

#[test]
fn add_chain_link_fails_for_unsupported_chain() {
	new_test_ext().execute_with(|| {
		let alias = b"chaintest".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		let dummy_sig = [0u8; 65];
		let addr: crate::ExternalAddr = b"some_address".to_vec().try_into().unwrap();

		assert_noop!(
			AccountMapping::add_chain_link(
				RuntimeOrigin::signed(1),
				9999,
				addr.to_vec(),
				dummy_sig.to_vec(),
			),
			Error::<Test>::UnsupportedChain
		);
	});
}

#[test]
fn add_chain_link_works_after_governance_registration() {
	new_test_ext().execute_with(|| {
		let alias = b"dynamic".to_vec().try_into().unwrap();
		assert_ok!(AccountMapping::register_alias(
			RuntimeOrigin::signed(1),
			alias
		));

		assert_ok!(AccountMapping::add_supported_chain(
			RuntimeOrigin::root(),
			501,
			SignatureScheme::Ed25519,
		));

		let addr: crate::ExternalAddr = [0u8; 32].to_vec().try_into().unwrap();
		let sig = [0u8; 64].to_vec();

		assert_ok!(AccountMapping::add_chain_link(
			RuntimeOrigin::signed(1),
			501,
			addr.to_vec(),
			sig
		));
	});
}

// ── Phase 2 alignment: dispatch_as_linked_account guard for native EVM ───────

fn remark_call() -> alloc::boxed::Box<RuntimeCall> {
	alloc::boxed::Box::new(RuntimeCall::System(frame_system::Call::remark {
		remark: alloc::vec![],
	}))
}

/// Calling dispatch_as_linked_account with the native EVM chain ID must fail
/// immediately — no signature or storage check should be reached.
#[test]
fn dispatch_as_linked_account_rejects_native_evm_chain_id() {
	new_test_ext().execute_with(|| {
		// TestNativeEvmChainId = 9999 in mock.
		// The guard fires before any storage lookup, so no setup is needed.
		assert_noop!(
			AccountMapping::dispatch_as_linked_account(
				RuntimeOrigin::signed(99),
				1u64, // owner (irrelevant — rejected before lookup)
				9999, // chain_id == TestNativeEvmChainId
				b"0xdeadbeef".to_vec(),
				[0u8; 65].to_vec(),
				remark_call(),
			),
			Error::<Test>::UseNativeSignatureForEvmAccounts
		);
	});
}

/// Calling dispatch_as_linked_account with a non-native chain ID must pass the
/// NativeEvmChainId guard and proceed to the storage lookup phase.
#[test]
fn dispatch_as_linked_account_accepts_non_evm_chain_id() {
	new_test_ext().execute_with(|| {
		// chain_id = 1 (Ethereum mainnet, NOT the native EVM chain 9999).
		// No link is registered, so NotOwnerOfLink is the expected error —
		// not UseNativeSignatureForEvmAccounts.
		assert_noop!(
			AccountMapping::dispatch_as_linked_account(
				RuntimeOrigin::signed(99),
				1u64,
				1, // non-native chain id — guard should pass
				b"0xdeadbeef".to_vec(),
				[0u8; 65].to_vec(),
				remark_call(),
			),
			Error::<Test>::NotOwnerOfLink
		);
	});
}
