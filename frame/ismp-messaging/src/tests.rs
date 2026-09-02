//! Tests for the parts a mistake would silently break.
//!
//! The inbound callbacks are exercised **directly**, not through the full message
//! pipeline. Forging a valid state proof would be testing upstream's verification, which
//! is upstream's job and already covered there. What is untested is *our* callback,
//! which is a function of `PostRequest` to `Result<Weight>` plus events — so calling it
//! is both easier and a sharper test.

use crate::{PALLET_ID, PALLET_ID_BYTES, payload::Message};
use pallet_ismp::pallet::ModuleId;
use scale_codec::{Decode, Encode};

#[test]
fn pallet_id_is_a_valid_module_id() {
	// `ModuleId::from_bytes` infers the variant from length alone: 8, 20 or 32 bytes,
	// nothing else. A previous value here was 7 bytes and parsed as nothing — harmless
	// only because our own router ignored the id, while Hyperbridge's runtime calls
	// `from_bytes(&request.to)?` and would have rejected everything we sent.
	assert_eq!(
		PALLET_ID_BYTES.len(),
		8,
		"a pallet module id is exactly 8 bytes"
	);
	assert!(
		ModuleId::from_bytes(PALLET_ID_BYTES).is_ok(),
		"our own module id must parse as a ModuleId"
	);
	assert_eq!(
		PALLET_ID.to_bytes(),
		PALLET_ID_BYTES,
		"the typed id and the raw bytes must not drift apart"
	);
}

#[test]
fn message_codec_indices_are_pinned() {
	// The discriminant is wire format. If a variant were inserted above `Data`, old
	// encoded messages would decode as the wrong variant rather than failing.
	assert_eq!(Message::Ping { nonce: 0 }.encode()[0], 0);
	assert_eq!(
		Message::Data {
			nonce: 0,
			data: alloc::vec![]
		}
		.encode()[0],
		1
	);
}

#[test]
fn message_roundtrips() {
	let msg = Message::Data {
		nonce: 42,
		data: alloc::vec![1, 2, 3],
	};
	let decoded = Message::decode(&mut &msg.encode()[..]).expect("roundtrip");
	assert_eq!(decoded, msg);
}

#[test]
fn garbage_does_not_decode_as_a_message() {
	// The premise behind the reject-rather-than-error path in `inbound`: undecodable
	// bodies are a real case that has to be handled, not a theoretical one.
	assert!(Message::decode(&mut &[0xff, 0xff, 0xff][..]).is_err());
}

// ── behaviour, against the mock runtime ──────────────────────────────────────────

use crate::{
	AcceptedSources, Error, InboundCount,
	inbound::IsmpModuleCallback,
	mock::{RuntimeOrigin, Test, new_test_ext},
};
use frame_support::{assert_noop, assert_ok};
use ismp::{
	host::StateMachine,
	module::IsmpModule,
	router::{GetRequest, GetResponse, PostRequest, Request, StorageValue},
};

/// An arbitrary counterparty reached *through* Hyperbridge, not Hyperbridge itself.
/// Nothing about this pallet is specific to any one chain — that is the point.
const COUNTERPARTY: StateMachine = StateMachine::Kusama(1000);
/// Hyperbridge's testnet deployment — the coprocessor.
const COPROCESSOR: StateMachine = StateMachine::Kusama(4009);

fn post_from(source: StateMachine, body: alloc::vec::Vec<u8>) -> PostRequest {
	PostRequest {
		source,
		dest: StateMachine::Substrate(*b"orbi"),
		nonce: 0,
		from: b"remote01".to_vec(),
		to: PALLET_ID_BYTES.to_vec(),
		timeout_timestamp: 0,
		body,
	}
}

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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
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
fn dispatch_rejects_non_root() {
	new_test_ext().execute_with(|| {
		assert!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				Message::Ping { nonce: 1 }.encode(),
				0,
			)
			.is_err()
		);
	});
}

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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
					reason: crate::RejectReason::Undecodable,
					..
				})
			)
		});
		assert!(rejected, "the rejection must be observable");
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
fn on_accept_weight_grows_with_body_length() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let module = IsmpModuleCallback::<Test>::default();

		let small = module
			.on_accept(post_from(COPROCESSOR, Message::Ping { nonce: 1 }.encode()))
			.unwrap();
		let large = module
			.on_accept(post_from(
				COPROCESSOR,
				Message::Data {
					nonce: 2,
					data: alloc::vec![0u8; 4096],
				}
				.encode(),
			))
			.unwrap();

		// Discarded today (`POLICY = false`), but becomes the block's accounted weight
		// the moment relayer fees are switched on.
		assert!(
			small.ref_time() > 0,
			"a callback must never report zero weight"
		);
		assert!(
			large.ref_time() > small.ref_time(),
			"weight must scale with the body"
		);
	});
}

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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::GetResponseReceived {
					keys: 2,
					found: 1,
				})
			)
		});
		assert!(seen, "absent keys must not be counted as found");
	});
}
