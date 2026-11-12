// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading remote state with a GET, and the answer that comes back.
//!
//! A GET exists as a separate path because a POST can be refused by a module on the
//! destination and a GET cannot: nobody runs code there. The relayer reads the requested
//! keys, proves them, and the answer comes back to our `on_response`. These pin the guards
//! that make an unanswerable GET fail immediately instead of hanging until expiry.

use crate::tests::util::*;
use crate::{
	AcceptedSources, PALLET_ID_BYTES, inbound::IsmpModuleCallback, payload::Message, tests::mock::*,
};
use frame_support::{assert_noop, assert_ok};
use ismp::{
	host::StateMachine,
	messaging::hash_request,
	module::IsmpModule,
	router::{GetRequest, GetResponse, Request, StorageValue},
};
use scale_codec::Encode;

#[test]
fn dispatch_get_reports_kind_get_and_no_body() {
	new_test_ext().execute_with(|| {
		pallet_timestamp::Pallet::<Test>::set_timestamp(NOW_SECS * 1_000);
		let nonce_before = pallet_ismp::Nonce::<Test>::get();

		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			get_keys(2),
			10_403_542,
			3_600,
		));

		let (_, nonce, timeout_timestamp, body_len, kind) =
			dispatched_event().expect("dispatch_get must emit RequestDispatched");

		assert_eq!(
			kind,
			crate::RequestKind::Get,
			"a GET must not report itself as a POST"
		);
		// 0 rather than omitted: the field means the same thing on every row, and a GET
		// genuinely has no body.
		assert_eq!(body_len, 0);
		assert_eq!(nonce, nonce_before);
		assert_eq!(timeout_timestamp, NOW_SECS + 3_600);
	});
}

#[test]
fn dispatch_get_with_zero_timeout_never_expires() {
	new_test_ext().execute_with(|| {
		pallet_timestamp::Pallet::<Test>::set_timestamp(NOW_SECS * 1_000);

		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			get_keys(1),
			10_403_542,
			0,
		));

		let (_, _, timeout_timestamp, _, _) = dispatched_event().expect("must emit");
		// Same branch as a POST: 0 means never, not `now + 0`.
		assert_eq!(timeout_timestamp, 0);
	});
}

#[test]
fn dispatch_get_rejects_a_request_for_nothing() {
	new_test_ext().execute_with(|| {
		// A keyless GET still costs a dispatch, a relayer round trip and a response, and
		// answers nothing.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::root(),
				COUNTERPARTY,
				alloc::vec![],
				10_403_542,
				0,
			),
			crate::Error::<Test>::NoKeysRequested
		);
	});
}

#[test]
fn dispatch_get_bounds_the_work_it_asks_of_the_destination() {
	new_test_ext().execute_with(|| {
		// Each key is a separate membership proof the remote chain must produce. The mock
		// caps this at 4, so 5 is over.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::root(),
				COUNTERPARTY,
				get_keys(5),
				10_403_542,
				0,
			),
			crate::Error::<Test>::TooManyKeys
		);
		// The boundary itself is allowed.
		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			get_keys(4),
			10_403_542,
			0,
		));
	});
}

#[test]
fn one_oversized_key_is_refused_even_when_the_count_is_fine() {
	new_test_ext().execute_with(|| {
		// The count bound and the length bound are different guards. Four keys is legal,
		// and one of them being a megabyte is not: `dispatch_get`'s weight is charged per
		// key on the assumption that a key is a storage key, so this is the case that
		// would be priced as four short reads.
		use frame_support::traits::Get;
		let max = <<Test as crate::Config>::MaxGetKeyLen as Get<u32>>::get() as usize;

		// Both origins, because the guard must not live in the paying branch alone: with it
		// inside `fee_for` a signed user would get unbounded keys while Root stayed bounded,
		// and a Root-only test cannot tell the difference.
		for origin in [RuntimeOrigin::root(), RuntimeOrigin::signed(1)] {
			let mut keys = get_keys(3);
			keys.push(alloc::vec![0u8; max + 1]);

			assert_noop!(
				crate::Pallet::<Test>::dispatch_get(
					origin.clone(),
					COUNTERPARTY,
					keys,
					10_403_542,
					600,
				),
				crate::Error::<Test>::KeyTooLarge
			);

			// The boundary itself is allowed.
			assert_ok!(crate::Pallet::<Test>::dispatch_get(
				origin,
				COUNTERPARTY,
				alloc::vec![alloc::vec![0u8; max]],
				10_403_542,
				600,
			));
		}

		// A key of the longest shape the protocol documents — 52 bytes, an EVM address plus
		// a slot hash — must pass. This is the bound's reason for existing: it exists to
		// refuse payloads wearing a key's name, not to refuse real keys.
		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			alloc::vec![alloc::vec![0u8; 52]],
			10_403_542,
			600,
		));
	});
}

#[test]
fn dispatch_get_rejects_an_unprovable_height() {
	new_test_ext().execute_with(|| {
		// `handlers/response.rs:72` compares the proof height for EQUALITY, so height 0 is
		// not a slow request — it is one no relayer can ever answer. Failing now says so,
		// rather than leaving it to expire silently.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::root(),
				COUNTERPARTY,
				get_keys(1),
				0,
				0,
			),
			crate::Error::<Test>::InvalidGetHeight
		);
	});
}

#[test]
fn dispatch_get_rejects_reading_our_own_state() {
	new_test_ext().execute_with(|| {
		// A round trip to prove something we can read directly.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::root(),
				StateMachine::Substrate(*b"orbi"),
				get_keys(1),
				10_403_542,
				0,
			),
			crate::Error::<Test>::DestinationIsSelf
		);
	});
}

#[test]
fn on_response_distinguishes_present_from_absent_keys() {
	new_test_ext().execute_with(|| {
		let response = GetResponse {
			get: GetRequest {
				source: StateMachine::Substrate(*b"orbi"),
				dest: COUNTERPARTY,
				nonce: 0,
				from: PALLET_ID_BYTES.to_vec(),
				keys: alloc::vec![],
				height: 0,
				context: alloc::vec![],
				timeout_timestamp: 0,
			},
			values: alloc::vec![
				StorageValue {
					key: alloc::vec![1],
					value: Some(alloc::vec![1])
				},
				// A proof of *absence* is a valid answer, and the interesting half.
				StorageValue {
					key: alloc::vec![2],
					value: None
				},
			],
		};

		assert!(
			IsmpModuleCallback::<Test>::default()
				.on_response(response)
				.is_ok()
		);

		let seen = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				RuntimeEvent::IsmpMessaging(crate::Event::GetResponseReceived {
					keys: 2,
					found: 1,
					..
				})
			)
		});
		assert!(seen, "absent keys must not be counted as found");
	});
}

#[test]
fn a_get_response_names_the_request_not_the_response() {
	new_test_ext().execute_with(|| {
		let get = GetRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce: 0,
			from: PALLET_ID_BYTES.to_vec(),
			keys: alloc::vec![alloc::vec![1]],
			height: 0,
			context: alloc::vec![],
			timeout_timestamp: 0,
		};

		// `RequestDispatched` recorded the *request's* commitment, so that is the only
		// value that joins this answer to anything. Hashing the response instead would
		// yield something no other row on this chain carries.
		let expected = hash_request::<pallet_ismp::Pallet<Test>>(&Request::Get(get.clone()));

		assert_ok!(
			IsmpModuleCallback::<Test>::default().on_response(GetResponse {
				get,
				values: alloc::vec![StorageValue {
					key: alloc::vec![1],
					value: Some(alloc::vec![1])
				}],
			})
		);

		assert_eq!(emitted_commitment(), Some(expected));
	});
}

#[test]
fn a_get_response_reports_dest_height_and_nonce() {
	new_test_ext().execute_with(|| {
		let get = GetRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce: 8,
			from: PALLET_ID_BYTES.to_vec(),
			keys: alloc::vec![alloc::vec![1u8; 32]],
			// The remote height the read was proven against — the only genuine remote
			// block number this pallet ever sees.
			height: 10_403_542,
			context: alloc::vec![],
			timeout_timestamp: 1_788_970_000,
		};
		let response = ismp::router::GetResponse {
			get,
			values: alloc::vec![ismp::router::StorageValue {
				key: alloc::vec![1u8; 32],
				value: Some(alloc::vec![9u8]),
			}],
		};

		assert_ok!(IsmpModuleCallback::<Test>::default().on_response(response));

		let found = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::GetResponseReceived {
					dest,
					height,
					nonce,
					timeout_timestamp,
					..
				}) => Some((dest, height, nonce, timeout_timestamp)),
				_ => None,
			})
			.expect("must emit GetResponseReceived");

		assert_eq!(found.0, COUNTERPARTY);
		assert_eq!(found.1, 10_403_542);
		assert_eq!(found.2, 8);
		assert_eq!(found.3, 1_788_970_000);
	});
}

#[test]
fn a_get_response_closes_out_the_get_it_answers() {
	new_test_ext().execute_with(|| {
		pallet_timestamp::Pallet::<Test>::set_timestamp(NOW_SECS * 1_000);
		let keys = get_keys(2);

		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			keys.clone(),
			10_403_542,
			0,
		));
		let (dispatched, nonce, timeout_timestamp, _, _) = dispatched_event().expect("must emit");

		// Rebuild the GET from the event's own fields and answer it. This is the GET
		// counterpart of `dispatched_fields_rebuild_the_committed_request`: if the emitted
		// nonce, height or timeout did not describe the request that was actually
		// committed, the two commitments would differ and this fails.
		let response = ismp::router::GetResponse {
			get: GetRequest {
				source: StateMachine::Substrate(*b"orbi"),
				dest: COUNTERPARTY,
				nonce,
				from: PALLET_ID_BYTES.to_vec(),
				keys: keys.clone(),
				height: 10_403_542,
				context: alloc::vec![],
				timeout_timestamp,
			},
			values: keys
				.iter()
				.map(|k| ismp::router::StorageValue {
					key: k.clone(),
					value: Some(alloc::vec![7u8]),
				})
				.collect(),
		};

		frame_system::Pallet::<Test>::reset_events();
		assert_ok!(IsmpModuleCallback::<Test>::default().on_response(response));

		assert_eq!(
			emitted_commitment(),
			Some(dispatched),
			"the response must name the very GET that was dispatched"
		);

		// And the spec-13 fields describe the read that was actually performed.
		let found = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::GetResponseReceived {
					dest,
					height,
					keys,
					found,
					..
				}) => Some((dest, height, keys, found)),
				_ => None,
			})
			.expect("must emit GetResponseReceived");
		assert_eq!(found.0, COUNTERPARTY);
		assert_eq!(
			found.1, 10_403_542,
			"the remote height the read was proven against"
		);
		assert_eq!(found.2, 2);
		assert_eq!(found.3, 2);
	});
}

/// A GET response is accepted with `AcceptedSources` EMPTY, while a POST from the very same
/// chain is refused.
///
/// This is why the self-relayed GET works on testnet without touching `AcceptedSources`:
/// `on_response` answers a request WE dispatched — the response handler already proved it
/// against our own commitment (`handlers/response.rs:65-71`) — so there is no remote sender
/// to vet. `AcceptedSources` gates who may *initiate* a message to us, which is a POST.
#[test]
fn a_get_response_is_accepted_without_any_accepted_source() {
	new_test_ext().execute_with(|| {
		assert!(
			AcceptedSources::<Test>::iter().next().is_none(),
			"the default must be to accept no POST source"
		);

		let module = IsmpModuleCallback::<Test>::default();
		assert_ok!(module.on_response(GetResponse {
			get: GetRequest {
				source: StateMachine::Substrate(*b"orbi"),
				dest: COPROCESSOR,
				nonce: 0,
				from: PALLET_ID_BYTES.to_vec(),
				keys: alloc::vec![alloc::vec![1u8; 32]],
				height: 10,
				context: alloc::vec![],
				timeout_timestamp: 0,
			},
			values: alloc::vec![StorageValue {
				key: alloc::vec![1u8; 32],
				value: Some(alloc::vec![9])
			}],
		}));
		assert!(
			emitted_commitment().is_some(),
			"GetResponseReceived must be emitted"
		);

		// Same chain, opposite direction: refused, because nobody accepted it as a source.
		assert!(
			module
				.on_accept(post_from(COPROCESSOR, Message::Ping { nonce: 1 }.encode()))
				.is_err()
		);
	});
}
