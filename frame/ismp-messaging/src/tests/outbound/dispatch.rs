// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Sending a POST: the guards that refuse a message before it is committed, and the
//! `RequestDispatched` fields. Two are easy to get wrong: a timeout of 0 means never, and
//! the nonce must be read before the dispatcher consumes it.

use crate::tests::util::*;
use crate::{Error, PALLET_ID_BYTES, payload::Message, tests::mock::*};
use frame_support::{assert_noop, assert_ok};
use ismp::{
	host::StateMachine,
	router::{PostRequest, Request},
};
use scale_codec::Encode;

#[test]
fn dispatch_addresses_the_requested_chain_not_the_coprocessor() {
	new_test_ext().execute_with(|| {
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			Message::Ping { nonce: 1 }.encode(),
			0,
		));

		// The event carries the destination that was asked for. Pinning `dest` to the
		// coprocessor — which an earlier revision did — would make Orbinum able to talk
		// to the bridge but never through it.
		let dispatched = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
					dest, ..
				}) if dest == COUNTERPARTY
			)
		});
		assert!(
			dispatched,
			"must be addressed to {COUNTERPARTY:?}, not the coprocessor"
		);
	});
}

#[test]
fn dispatch_rejects_an_invalid_module_id() {
	new_test_ext().execute_with(|| {
		// 7 bytes: the exact length that parses as nothing, and the bug this pallet
		// shipped with before.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::root(),
				COUNTERPARTY,
				b"orbdisp".to_vec(),
				Message::Ping { nonce: 1 }.encode(),
				0,
			),
			Error::<Test>::InvalidModuleId
		);
	});
}

#[test]
fn dispatch_rejects_a_message_to_ourselves() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::root(),
				StateMachine::Substrate(*b"orbi"),
				b"demo/mod".to_vec(),
				Message::Ping { nonce: 1 }.encode(),
				0,
			),
			Error::<Test>::DestinationIsSelf
		);
	});
}

#[test]
fn dispatch_rejects_an_oversized_body() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::root(),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				alloc::vec![0u8; 8193],
				0,
			),
			Error::<Test>::BodyTooLarge
		);
	});
}

#[test]
fn dispatch_reports_the_wire_nonce_expiry_and_size() {
	new_test_ext().execute_with(|| {
		// Pinned, so the absolute deadline can be asserted exactly rather than as a range.
		// The mock's timestamp reads 0 at genesis, which would make `now + timeout`
		// indistinguishable from a relative value leaking through.
		pallet_timestamp::Pallet::<Test>::set_timestamp(NOW_SECS * 1_000);

		let body = Message::Ping { nonce: 1 }.encode();
		let expected_len = body.len() as u32;
		// Read before the dispatch: `next_nonce` hands out this value and then increments,
		// so it is the nonce the message actually goes out with.
		let nonce_before = pallet_ismp::Nonce::<Test>::get();

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			body,
			3_600,
		));

		let (_, nonce, timeout_timestamp, body_len, kind) =
			dispatched_event().expect("dispatch must emit RequestDispatched");

		assert_eq!(
			nonce, nonce_before,
			"the event must report the nonce that went out"
		);
		assert_eq!(
			pallet_ismp::Nonce::<Test>::get(),
			nonce_before + 1,
			"and the dispatcher must have consumed it"
		);
		assert_eq!(body_len, expected_len);
		assert_eq!(kind, crate::RequestKind::Post);
		// The clock is pinned above, so this asserts the ARITHMETIC and not merely that
		// the number is large: `now + timeout`, in seconds, exactly as the dispatcher
		// computes it. A relative value leaking through would fail here.
		assert_eq!(
			timeout_timestamp,
			NOW_SECS + 3_600,
			"a relative timeout must be reported as an absolute deadline"
		);
	});
}

#[test]
fn dispatch_with_zero_timeout_reports_never_expires() {
	new_test_ext().execute_with(|| {
		// A non-zero clock, so a `now + 0` bug would be visible instead of coinciding
		// with the correct answer at genesis.
		pallet_timestamp::Pallet::<Test>::set_timestamp(NOW_SECS * 1_000);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			Message::Ping { nonce: 1 }.encode(),
			0,
		));

		let (_, _, timeout_timestamp, _, _) = dispatched_event().expect("must emit");
		// THE case this test exists for. Upstream has an explicit branch: a timeout of 0
		// stays 0 and means the message never expires. Computing `now + 0` instead would
		// emit a deadline in the past, and anything downstream would call the message
		// expired the moment it was sent.
		assert_eq!(
			timeout_timestamp, 0,
			"a zero timeout means never expires, not `now + 0`"
		);
	});
}

#[test]
fn dispatched_fields_rebuild_the_committed_request() {
	new_test_ext().execute_with(|| {
		pallet_timestamp::Pallet::<Test>::set_timestamp(NOW_SECS * 1_000);

		let body = Message::Ping { nonce: 42 }.encode();
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			body.clone(),
			3_600,
		));

		let (commitment, nonce, timeout_timestamp, body_len, _) =
			dispatched_event().expect("must emit");

		// The point of this test: reconstruct the request from the EVENT ALONE and check it
		// hashes to the commitment the pallet emitted. That makes the event fields
		// self-consistent with the message the network sees — and if upstream ever changes
		// how `timeout_timestamp` is derived, this fails instead of silently emitting a
		// value that no longer matches the wire.
		let rebuilt = Request::Post(PostRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce,
			from: PALLET_ID_BYTES.to_vec(),
			to: b"demo/mod".to_vec(),
			timeout_timestamp,
			body,
		});

		assert_eq!(
			ismp::messaging::hash_request::<pallet_ismp::Pallet<Test>>(&rebuilt),
			commitment,
			"the emitted fields must describe the request that was actually committed"
		);
		assert_eq!(
			body_len as usize,
			Message::Ping { nonce: 42 }.encode().len()
		);
	});
}
