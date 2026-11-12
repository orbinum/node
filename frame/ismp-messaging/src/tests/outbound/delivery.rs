// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Delivery confirmation: the receipt key a confirmation reads, and how the GET response
//! that carries the receipt is read.

use crate::tests::util::*;
use crate::{
	Error, PALLET_ID_BYTES,
	inbound::IsmpModuleCallback,
	receipts::{confirmation_keys, confirmed_commitment, request_receipt_key},
	tests::mock::*,
};
use frame_support::{assert_noop, assert_ok};
use ismp::{
	host::StateMachine,
	module::IsmpModule,
	router::{GetRequest, GetResponse, StorageValue},
};
use scale_codec::Encode;
use sp_core::H256;

/// Captured from Hyperbridge (Gargantua) on 2026-09-11 by reading the child trie
/// directly over `childstate_getStorage`. The message is the first Orbinum POST
/// executed on BSC testnet (block 130431639).
const REAL_COMMITMENT: [u8; 32] =
	hex_literal::hex!("92c95a9bb4e51198b679186b1f8f5224e0bccb1b749744eeea081c8a67fc8de7");

#[test]
fn receipt_key_matches_the_one_hyperbridge_answered() {
	let key = request_receipt_key(H256::from(REAL_COMMITMENT));

	// The exact bytes that returned the relayer account from Gargantua's child trie.
	// A typo in the prefix yields an empty proof, which reads as "not delivered" — the
	// single failure this whole feature exists to avoid — so the value is pinned here
	// rather than trusted to the constant above.
	let expected = {
		let mut v = b"RequestReceipts".to_vec();
		v.extend_from_slice(&REAL_COMMITMENT);
		v
	};
	assert_eq!(key, expected);
	assert_eq!(key.len(), 15 + 32);
}

#[test]
fn prefix_is_not_hashed() {
	// `pallet-ismp` concatenates a plain ASCII prefix; it does not hash it the way a
	// `StorageMap` would. Asserting the readable prefix survives means a future
	// "improvement" that hashes it fails here instead of silently querying a key no
	// chain has ever written.
	let key = request_receipt_key(H256::repeat_byte(0xab));
	assert!(key.starts_with(b"RequestReceipts"));
	assert_eq!(&key[15..], &[0xab; 32]);
}

#[test]
fn one_key_per_confirmation() {
	// Each key in a GET is a separate membership proof the destination must produce.
	// Confirmation asks for exactly one, which keeps it well inside `MaxGetKeys`.
	let keys = confirmation_keys(H256::from(REAL_COMMITMENT));
	assert_eq!(keys.len(), 1);
	assert_eq!(keys[0], request_receipt_key(H256::from(REAL_COMMITMENT)));
}

#[test]
fn context_round_trips_the_commitment() {
	let commitment = H256::from(REAL_COMMITMENT);
	assert_eq!(
		confirmed_commitment(commitment.as_bytes()),
		Some(commitment)
	);
}

#[test]
fn a_context_that_is_not_a_commitment_is_not_a_confirmation() {
	// An empty context is what every GET this pallet dispatched before confirmation
	// existed carries. Reading one as a confirmation would attribute a delivery to
	// commitment zero.
	assert_eq!(confirmed_commitment(&[]), None);
	assert_eq!(confirmed_commitment(&[0u8; 31]), None);
	assert_eq!(confirmed_commitment(&[0u8; 33]), None);
}

#[test]
fn a_present_receipt_confirms_the_post_named_by_the_context() {
	new_test_ext().execute_with(|| {
		let post = sp_core::H256::repeat_byte(7);
		let relayer = alloc::vec![0xaa; 32];
		// As the chain stores it: `child::put` SCALE-encodes, so a 32-byte account travels
		// as 33 bytes — a compact length prefix and then the account. Testing with the bare
		// account would pass while the runtime published the prefix to everyone.
		let stored = relayer.encode();
		assert_eq!(
			stored.len(),
			33,
			"a stored 32-byte account is 33 bytes on the wire"
		);

		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_response(confirmation_response(
					post.as_bytes().to_vec(),
					Some(stored)
				))
				.is_ok()
		);

		// The confirmed commitment is the POST from the context, NOT the GET's own — they
		// are different messages, and reporting the GET's would make the event useless for
		// joining a delivery to what was delivered.
		assert_eq!(confirmed_events(), alloc::vec![(post, relayer, 42)]);
	});
}

#[test]
fn an_absent_receipt_confirms_nothing() {
	new_test_ext().execute_with(|| {
		let post = sp_core::H256::repeat_byte(7);

		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_response(confirmation_response(post.as_bytes().to_vec(), None))
				.is_ok()
		);

		// The guard this whole feature exists for. A proof of absence says the receipt was
		// not there at THAT height, which is what asking too early also looks like. There
		// is no negative event, so silence is the only honest output.
		assert!(confirmed_events().is_empty());
	});
}

#[test]
fn an_ordinary_get_is_never_read_as_a_confirmation() {
	new_test_ext().execute_with(|| {
		// Every GET dispatched before confirmation existed carries an empty context. If a
		// non-commitment context were accepted, those would attribute deliveries to
		// commitment zero.
		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_response(confirmation_response(
					alloc::vec![],
					Some(alloc::vec![0xaa; 32])
				))
				.is_ok()
		);
		assert!(confirmed_events().is_empty());
	});
}

#[test]
fn confirming_reads_the_receipt_key_from_the_coprocessor() {
	new_test_ext().execute_with(|| {
		let post = sp_core::H256::repeat_byte(9);
		assert_ok!(crate::Pallet::<Test>::confirm_delivery(
			RuntimeOrigin::root(),
			post,
			42,
			600
		));

		// Addressed to the coprocessor, not to the POST's destination: it is the only
		// chain whose state this runtime holds a commitment for, so it is the only
		// receipt that can be proven here.
		let dispatched = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
					dest, kind, ..
				}) => Some((dest, kind)),
				_ => None,
			})
			.expect("confirm_delivery dispatches a request");

		assert_eq!(dispatched.0, COPROCESSOR);
		assert_eq!(dispatched.1, crate::RequestKind::Get);
	});
}

#[test]
fn confirm_delivery_rejects_an_unprovable_height() {
	new_test_ext().execute_with(|| {
		// Height 0 can never be proven, and `handlers/response.rs:72` compares heights for
		// equality — so this would not fail slowly, it would hang until it expired.
		assert_noop!(
			crate::Pallet::<Test>::confirm_delivery(
				RuntimeOrigin::root(),
				sp_core::H256::repeat_byte(9),
				0,
				600
			),
			Error::<Test>::InvalidGetHeight
		);
	});
}

#[test]
fn a_get_context_is_bounded_like_a_body() {
	new_test_ext().execute_with(|| {
		// `context` is carried on the wire and returned inside the response, but
		// `dispatch_get`'s weight is measured per KEY — so without this bound an oversized
		// context is work nothing charges for.
		// 8192 is the mock's `MaxBodyLen`, matching `dispatch_rejects_an_oversized_body`.
		assert_noop!(
			crate::outbound::get::<Test>(
				None,
				COUNTERPARTY,
				alloc::vec![alloc::vec![1]],
				42,
				0,
				alloc::vec![0u8; 8193]
			),
			Error::<Test>::BodyTooLarge
		);

		// At the limit it still goes through: the bound is a cap, not a smaller cap.
		assert_ok!(crate::outbound::get::<Test>(
			None,
			COUNTERPARTY,
			alloc::vec![alloc::vec![1]],
			42,
			0,
			alloc::vec![0u8; 8192]
		));
	});
}

#[test]
fn the_receipt_is_matched_by_key_not_by_position() {
	new_test_ext().execute_with(|| {
		let post = sp_core::H256::repeat_byte(7);
		let want = crate::receipts::request_receipt_key(post);

		// `verify_state_proof` returns a `BTreeMap`, so values arrive sorted by key bytes —
		// not in the order the keys were asked for. A key that sorts BEFORE the receipt's
		// puts a foreign value at index 0, which is what indexing would pick up.
		let decoy = alloc::vec![0u8; 4];
		assert!(
			decoy < want,
			"the decoy must sort first for this test to mean anything"
		);

		let response = GetResponse {
			get: GetRequest {
				source: StateMachine::Substrate(*b"orbi"),
				dest: COPROCESSOR,
				nonce: 0,
				from: PALLET_ID_BYTES.to_vec(),
				keys: alloc::vec![want.clone(), decoy.clone()],
				height: 42,
				context: post.as_bytes().to_vec(),
				timeout_timestamp: 0,
			},
			// Encoded, as `child::put` stores them.
			values: alloc::vec![
				StorageValue {
					key: decoy,
					value: Some(alloc::vec![0xdeu8, 0xad].encode())
				},
				StorageValue {
					key: want,
					value: Some(alloc::vec![0xaau8; 32].encode())
				},
			],
		};

		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_response(response)
				.is_ok()
		);

		// The relayer must be the RECEIPT's value, never the decoy sitting at index 0.
		assert_eq!(
			confirmed_events(),
			alloc::vec![(post, alloc::vec![0xaa; 32], 42)]
		);
	});
}

#[test]
fn a_receipt_that_does_not_decode_confirms_nothing() {
	new_test_ext().execute_with(|| {
		let post = sp_core::H256::repeat_byte(7);

		// A length prefix that claims more bytes than follow. Emitting this raw would
		// publish a relayer nothing can match against an account; emitting nothing keeps
		// the event's contract — a `DeliveryConfirmed` always names a real deliverer.
		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_response(confirmation_response(
					post.as_bytes().to_vec(),
					Some(alloc::vec![0xff, 0xff, 0x01])
				))
				.is_ok()
		);

		assert!(confirmed_events().is_empty());
	});
}
