//! Expiry: `on_timeout` never errs, and its event names the request that expired.

use crate::tests::util::*;
use crate::{PALLET_ID_BYTES, inbound::IsmpModuleCallback, payload::Message, tests::mock::*};
use frame_support::assert_ok;
use ismp::{
	host::StateMachine,
	module::IsmpModule,
	router::{GetRequest, PostRequest, Request},
};
use scale_codec::Encode;

#[test]
fn on_timeout_never_errs_for_either_variant() {
	new_test_ext().execute_with(|| {
		let module = IsmpModuleCallback::<Test>::default();

		assert!(
			module
				.on_timeout(Request::Post(post_from(COUNTERPARTY, alloc::vec![])))
				.is_ok()
		);

		// Upstream's demo pallet errs on `Get` ("Only Post requests allowed"). Copying
		// that would strand our own commitments the moment we dispatch a GET, because
		// the handler resolves the module before deleting the commitment.
		assert!(
			module
				.on_timeout(Request::Get(GetRequest {
					source: StateMachine::Substrate(*b"orbi"),
					dest: COUNTERPARTY,
					nonce: 0,
					from: PALLET_ID_BYTES.to_vec(),
					keys: alloc::vec![],
					height: 0,
					context: alloc::vec![],
					timeout_timestamp: 0,
				}))
				.is_ok()
		);
	});
}

#[test]
fn a_timeout_closes_out_the_dispatch_it_belongs_to() {
	new_test_ext().execute_with(|| {
		// Dispatch for real, so the commitment compared against is the one the pallet
		// actually recorded rather than one recomputed by the test.
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			Message::Ping { nonce: 1 }.encode(),
			0,
		));

		let dispatched = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
					commitment, ..
				}) => Some(commitment),
				_ => None,
			})
			.expect("dispatch must emit RequestDispatched");

		// The request as the dispatcher built it: `from` is our pallet id and the nonce is
		// the one just consumed. Reconstructing it is what proves the two commitments are
		// the same value and not merely both non-zero.
		let request = Request::Post(PostRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce: pallet_ismp::Nonce::<Test>::get().saturating_sub(1),
			from: PALLET_ID_BYTES.to_vec(),
			to: b"demo/mod".to_vec(),
			timeout_timestamp: 0,
			body: Message::Ping { nonce: 1 }.encode(),
		});

		frame_system::Pallet::<Test>::reset_events();
		assert_ok!(IsmpModuleCallback::<Test>::default().on_timeout(request));

		assert_eq!(
			emitted_commitment(),
			Some(dispatched),
			"the expiry must name the very request that was dispatched"
		);
	});
}

#[test]
fn a_timeout_names_kind_nonce_expiry_and_size() {
	new_test_ext().execute_with(|| {
		let body = Message::Ping { nonce: 3 }.encode();
		let expected_len = body.len() as u32;
		let request = Request::Post(PostRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce: 11,
			from: PALLET_ID_BYTES.to_vec(),
			to: b"demo/mod".to_vec(),
			timeout_timestamp: 1_788_970_000,
			body,
		});

		assert_ok!(IsmpModuleCallback::<Test>::default().on_timeout(request));

		let found = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::RequestTimedOut {
					kind,
					nonce,
					timeout_timestamp,
					body_len,
					..
				}) => Some((kind, nonce, timeout_timestamp, body_len)),
				_ => None,
			})
			.expect("must emit RequestTimedOut");

		assert_eq!(found.0, crate::RequestKind::Post);
		assert_eq!(found.1, 11);
		assert_eq!(found.2, 1_788_970_000);
		assert_eq!(found.3, expected_len);
	});
}

#[test]
fn a_get_timeout_is_named_a_get_and_carries_no_body() {
	new_test_ext().execute_with(|| {
		// A GET expiring and a POST expiring are different failures, and `body_len` has no
		// meaning for a GET — 0, not the size of something else.
		let request = Request::Get(GetRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce: 4,
			from: PALLET_ID_BYTES.to_vec(),
			keys: alloc::vec![alloc::vec![1u8; 32]],
			height: 500,
			context: alloc::vec![],
			timeout_timestamp: 0,
		});

		assert_ok!(IsmpModuleCallback::<Test>::default().on_timeout(request));

		let found = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::RequestTimedOut {
					kind,
					body_len,
					nonce,
					..
				}) => Some((kind, body_len, nonce)),
				_ => None,
			})
			.expect("must emit RequestTimedOut");

		assert_eq!(found.0, crate::RequestKind::Get);
		assert_eq!(found.1, 0, "a GET has no body");
		assert_eq!(found.2, 4);
	});
}
