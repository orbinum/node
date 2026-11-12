// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Receiving a POST: the source check, the size bound and the decode, and the events that
//! make an arrival or a rejection attributable to the message that caused it.
//!
//! The callbacks are exercised **directly**, not through the full message pipeline.
//! Forging a valid state proof would be testing upstream's verification, which is
//! upstream's job and already covered there. What is ours is the callback, a function of
//! `PostRequest` to `Result<Weight>` plus events — so calling it is both easier and a
//! sharper test.

use crate::tests::util::*;
use crate::{
	AcceptedSources, InboundCount, inbound::IsmpModuleCallback, payload::Message, tests::mock::*,
};
use frame_support::assert_ok;
use ismp::{host::StateMachine, messaging::hash_request, module::IsmpModule, router::Request};
use scale_codec::{Decode, Encode};

#[test]
fn accepts_a_message_from_an_accepted_source() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let module = IsmpModuleCallback::<Test>::default();

		assert!(
			module
				.on_accept(post_from(COPROCESSOR, Message::Ping { nonce: 7 }.encode()))
				.is_ok()
		);
		assert_eq!(InboundCount::<Test>::get(), 1);
	});
}

#[test]
fn rejects_a_message_from_an_unaccepted_source() {
	new_test_ext().execute_with(|| {
		// Nothing whitelisted: the default must be to accept nothing.
		let module = IsmpModuleCallback::<Test>::default();
		let err = module
			.on_accept(post_from(COPROCESSOR, Message::Ping { nonce: 7 }.encode()))
			.expect_err("unaccepted source must be refused");

		// Erring is deliberate here: the handler deletes the receipt on error, which
		// leaves the sender able to time out and recover.
		assert!(alloc::format!("{err:?}").contains("unaccepted source"));
		assert_eq!(InboundCount::<Test>::get(), 0);
	});
}

#[test]
fn an_undecodable_body_is_accepted_and_reported_not_errored() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let module = IsmpModuleCallback::<Test>::default();

		// `handle_unsigned` is `#[transactional]`: returning `Err` here would revert the
		// whole batch, so one malformed message from a third party would destroy
		// unrelated messages delivered alongside it.
		assert!(
			module
				.on_accept(post_from(COPROCESSOR, alloc::vec![0xff, 0xff]))
				.is_ok()
		);
		assert_eq!(InboundCount::<Test>::get(), 0, "not counted as handled");

		let rejected = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
					reason: crate::RejectReason::Undecodable,
					..
				})
			)
		});
		assert!(rejected, "the rejection must be observable");
	});
}

#[test]
fn a_body_with_trailing_bytes_is_rejected_as_undecodable() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let mut body = Message::Ping { nonce: 7 }.encode();
		body.push(0);

		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_accept(post_from(COPROCESSOR, body))
				.is_ok()
		);
		assert_eq!(InboundCount::<Test>::get(), 0, "not counted as handled");
	});
}

#[test]
fn on_accept_does_not_dispatch() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let before = pallet_ismp::Nonce::<Test>::get();

		IsmpModuleCallback::<Test>::default()
			.on_accept(post_from(COPROCESSOR, Message::Ping { nonce: 1 }.encode()))
			.unwrap();

		// Dispatching from inside a callback would write a commitment inside a
		// transaction that can still revert, and add weight to an extrinsic whose
		// declared weight we do not control.
		assert_eq!(pallet_ismp::Nonce::<Test>::get(), before);
	});
}

#[test]
fn an_arrival_reports_the_senders_own_commitment() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let request = post_from(COPROCESSOR, Message::Ping { nonce: 7 }.encode());

		// The value the sending chain committed to, computed the way the protocol does.
		// Deriving it any other way — a local counter, a hash of our own — would produce
		// an identifier no other chain has ever seen, which is worse than none.
		let expected = hash_request::<pallet_ismp::Pallet<Test>>(&Request::Post(request.clone()));

		assert_ok!(IsmpModuleCallback::<Test>::default().on_accept(request));
		assert_eq!(
			emitted_commitment(),
			Some(expected),
			"MessageReceived must carry the request's canonical commitment"
		);
	});
}

#[test]
fn a_rejection_is_still_attributable() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let request = post_from(COPROCESSOR, alloc::vec![0xff, 0xff]);
		let expected = hash_request::<pallet_ismp::Pallet<Test>>(&Request::Post(request.clone()));

		// A rejection used to be anonymous: the sender saw only a timeout and no observer
		// could say which message was refused.
		assert_ok!(IsmpModuleCallback::<Test>::default().on_accept(request));
		assert_eq!(emitted_commitment(), Some(expected));
	});
}

#[test]
fn an_arrival_reports_the_senders_nonce_and_expiry() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let mut request = post_from(COPROCESSOR, Message::Ping { nonce: 7 }.encode());
		// The SENDER's values, not ours — an arrival is checked against what the other
		// chain said it sent.
		request.nonce = 99;
		request.timeout_timestamp = 1_788_970_000;

		assert_ok!(IsmpModuleCallback::<Test>::default().on_accept(request));

		let found = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::MessageReceived {
					nonce,
					timeout_timestamp,
					body_len,
					..
				}) => Some((nonce, timeout_timestamp, body_len)),
				_ => None,
			})
			.expect("must emit MessageReceived");

		assert_eq!(found.0, 99);
		assert_eq!(found.1, 1_788_970_000);
		assert!(found.2 > 0);
	});
}

#[test]
fn a_rejection_reports_size_and_identity_without_the_body() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		// Undecodable rather than oversized, so the body is a realistic size and the
		// assertion is about what the event carries rather than about the size bound.
		let mut request = post_from(COPROCESSOR, alloc::vec![0xff; 12]);
		request.nonce = 5;
		request.timeout_timestamp = 0;

		assert_ok!(IsmpModuleCallback::<Test>::default().on_accept(request));

		let found = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
					reason,
					body_len,
					nonce,
					timeout_timestamp,
					..
				}) => Some((reason, body_len, nonce, timeout_timestamp)),
				_ => None,
			})
			.expect("must emit MessageRejected");

		assert_eq!(found.0, crate::RejectReason::Undecodable);
		assert_eq!(found.1, 12, "the size of what was refused");
		assert_eq!(found.2, 5);
		assert_eq!(found.3, 0);
	});
}

#[test]
fn an_arrival_is_attributable_to_the_message_that_caused_it() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let request = post_from(COPROCESSOR, Message::Ping { nonce: 42 }.encode());

		// The commitment the SENDER holds. Derived the protocol's own way, so the two
		// chains agree on it without either being told — which is what lets an indexer
		// join this arrival to the dispatch on the far side.
		let expected = ismp::messaging::hash_request::<pallet_ismp::Pallet<Test>>(
			&ismp::router::Request::Post(request.clone()),
		);

		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_accept(request)
				.is_ok()
		);

		let evs = received_events();
		assert_eq!(evs.len(), 1);
		let (source, from, body_len, commitment, nonce) = evs.into_iter().next().unwrap();
		assert_eq!(commitment, expected, "must be the sender's commitment");
		assert_eq!(source, COPROCESSOR);
		assert_eq!(
			from,
			b"remote01".to_vec(),
			"the sending module, recorded not trusted"
		);
		assert_eq!(body_len, Message::Ping { nonce: 42 }.encode().len() as u32);
		assert_eq!(nonce, 0, "the SENDER's nonce, not one of ours");
	});
}

#[test]
fn a_data_message_is_accepted_like_a_ping() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let body = Message::Data {
			nonce: 3,
			data: b"hello from gargantua".to_vec(),
		}
		.encode();

		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_accept(post_from(COPROCESSOR, body.clone()))
				.is_ok()
		);
		assert_eq!(InboundCount::<Test>::get(), 1);
		// The body itself is deliberately NOT emitted — it is remote-controlled data and
		// every event is stored in the block. Only its size travels.
		assert_eq!(received_events()[0].2, body.len() as u32);
	});
}

#[test]
fn an_oversized_body_is_rejected_without_decoding_it() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		// 8192 is the mock's `MaxBodyLen`. The size check runs BEFORE the decode so the
		// cost of decoding attacker-supplied bytes is bounded by a value we chose.
		let body = alloc::vec![0u8; 8193];

		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_accept(post_from(COPROCESSOR, body))
				.is_ok(),
			"must not err: erring reverts the whole relayer batch"
		);
		assert_eq!(InboundCount::<Test>::get(), 0);

		let too_large = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
					reason: crate::RejectReason::TooLarge,
					..
				})
			)
		});
		assert!(too_large, "the size rejection must be attributable");
	});
}

#[test]
fn a_rejection_still_names_the_message_it_refused() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let request = post_from(COPROCESSOR, alloc::vec![0xff, 0xff]);
		let expected = ismp::messaging::hash_request::<pallet_ismp::Pallet<Test>>(
			&ismp::router::Request::Post(request.clone()),
		);

		IsmpModuleCallback::<Test>::default()
			.on_accept(request)
			.unwrap();

		// Without the commitment a rejection is anonymous: the sender sees only a timeout
		// and can never learn why. This is the one event a remote party controls the
		// firing of, so it must still be joinable to what it refused.
		let named = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
					commitment, ..
				}) if commitment == expected
			)
		});
		assert!(named);
	});
}

#[test]
fn accepting_a_source_is_what_opens_the_door() {
	new_test_ext().execute_with(|| {
		let module = IsmpModuleCallback::<Test>::default();
		let msg = || post_from(COPROCESSOR, Message::Ping { nonce: 1 }.encode());

		// Closed by default. This is the state testnet was in until `accept_source` ran.
		assert!(module.on_accept(msg()).is_err());

		assert_ok!(crate::Pallet::<Test>::accept_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		assert!(module.on_accept(msg()).is_ok());

		// And closing it again takes effect immediately, which is the whole point of the
		// map being consulted per message rather than cached.
		assert_ok!(crate::Pallet::<Test>::remove_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		assert!(module.on_accept(msg()).is_err());
		assert_eq!(
			InboundCount::<Test>::get(),
			1,
			"only the accepted one counted"
		);
	});
}

#[test]
fn one_accepted_source_does_not_admit_another() {
	new_test_ext().execute_with(|| {
		// The allowlist is per chain, not a global on/off switch. Accepting Hyperbridge
		// must not silently admit BSC.
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let module = IsmpModuleCallback::<Test>::default();

		assert!(
			module
				.on_accept(post_from(COPROCESSOR, Message::Ping { nonce: 1 }.encode()))
				.is_ok()
		);
		assert!(
			module
				.on_accept(post_from(COUNTERPARTY, Message::Ping { nonce: 1 }.encode()))
				.is_err()
		);
		assert_eq!(InboundCount::<Test>::get(), 1);
	});
}

#[test]
fn several_arrivals_each_get_their_own_row() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let module = IsmpModuleCallback::<Test>::default();

		// Distinct nonces, so distinct commitments: a relayer batch of three messages must
		// produce three attributable arrivals, not one merged counter.
		for n in 0..3u64 {
			let mut req = post_from(COPROCESSOR, Message::Ping { nonce: n }.encode());
			req.nonce = n;
			assert!(module.on_accept(req).is_ok());
		}

		assert_eq!(InboundCount::<Test>::get(), 3);
		let evs = received_events();
		assert_eq!(evs.len(), 3);
		let commitments: alloc::collections::BTreeSet<_> = evs.iter().map(|e| e.3).collect();
		assert_eq!(commitments.len(), 3, "each arrival is distinguishable");
	});
}

#[test]
fn a_body_an_evm_caller_would_build_decodes_here() {
	new_test_ext().execute_with(|| {
		// The wire format an EVM sender has to produce by hand — Solidity has no SCALE
		// codec, so `OrbinumBridge.sendToOrbinum` takes raw bytes and whoever calls it
		// builds them. Getting the variant index or the integer endianness wrong yields
		// `MessageRejected { Undecodable }` on arrival, which is visible but late.
		//
		// `Ping { nonce: 1 }` = index 0x00, then a u64 little-endian.
		let ping = alloc::vec![0x00, 1, 0, 0, 0, 0, 0, 0, 0];
		assert_eq!(
			Message::decode(&mut &ping[..]),
			Ok(Message::Ping { nonce: 1 })
		);
		assert_eq!(Message::Ping { nonce: 1 }.encode(), ping);

		// `Data { nonce: 2, data: [0xab, 0xcd] }` = index 0x01, u64 LE, then a SCALE
		// compact length (0x08 = 2) and the bytes.
		let data = alloc::vec![0x01, 2, 0, 0, 0, 0, 0, 0, 0, 0x08, 0xab, 0xcd];
		assert_eq!(
			Message::decode(&mut &data[..]),
			Ok(Message::Data {
				nonce: 2,
				data: alloc::vec![0xab, 0xcd]
			})
		);

		// And the whole point: such a body, arriving from an accepted EVM source, is
		// handled rather than refused.
		let evm = StateMachine::Evm(97);
		AcceptedSources::<Test>::insert(evm, ());
		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_accept(post_from(evm, ping))
				.is_ok()
		);
		assert_eq!(InboundCount::<Test>::get(), 1);
	});
}

#[test]
fn an_evm_sender_module_id_is_recorded_not_rejected() {
	new_test_ext().execute_with(|| {
		// `EvmHost.dispatch` sets `from` to `abi.encodePacked(msg.sender)` — 20 raw bytes,
		// not the 8 a pallet id has. `on_accept` deliberately does not constrain `from`
		// (the chain is pinned by `AcceptedSources` and the contents by the membership
		// proof), so a contract sender must pass and simply be recorded.
		let evm = StateMachine::Evm(97);
		AcceptedSources::<Test>::insert(evm, ());

		let mut req = post_from(evm, Message::Ping { nonce: 5 }.encode());
		req.from = alloc::vec![0xab; 20];

		assert!(IsmpModuleCallback::<Test>::default().on_accept(req).is_ok());
		assert_eq!(received_events()[0].1, alloc::vec![0xab; 20]);
	});
}
