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
	messaging::hash_request,
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
					..
				})
			)
		});
		assert!(seen, "absent keys must not be counted as found");
	});
}

/// Reads the commitment out of whichever of our events carries one.
///
/// Matching the variant by name would let a test pass while the *other* events lost their
/// commitment, so this deliberately accepts any of them.
fn emitted_commitment() -> Option<sp_core::H256> {
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.find_map(|r| match r.event {
			crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageReceived {
				commitment,
				..
			})
			| crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
				commitment,
				..
			})
			| crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::GetResponseReceived {
				commitment,
				..
			})
			| crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestTimedOut {
				commitment,
				..
			}) => Some(commitment),
			_ => None,
		})
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
					commitment,
					..
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

// ─── Runtime spec 13: the wire fields ─────────────────────────────────────────
//
// Everything below is a field that existed in the callback arguments and was discarded.
// The tests pin the two things that are easy to get wrong: a timeout of 0 means NEVER,
// and the nonce must be read before the dispatcher consumes it.

/// A fixed wall clock for the dispatch tests, in unix SECONDS.
const NOW_SECS: u64 = 1_788_900_000;

/// The `RequestDispatched` payload, for the tests that assert on its new fields.
fn dispatched_event() -> Option<(sp_core::H256, u64, u64, u32, crate::RequestKind)> {
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.find_map(|r| match r.event {
			crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
				commitment,
				nonce,
				timeout_timestamp,
				body_len,
				kind,
				..
			}) => Some((commitment, nonce, timeout_timestamp, body_len, kind)),
			_ => None,
		})
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageReceived {
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestTimedOut {
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestTimedOut {
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::GetResponseReceived {
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

// ─── dispatch_get ─────────────────────────────────────────────────────────────
//
// A GET exists as a separate path because a POST can be refused by a module on the
// destination and a GET cannot: nobody runs code there. The relayer reads the requested
// keys, proves them, and the answer comes back to OUR `on_response`. These tests pin the
// guards that make an unanswerable GET fail immediately instead of hanging until expiry.

/// A GET to the counterparty with `n` distinct keys.
fn get_keys(n: usize) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
	(0..n).map(|i| alloc::vec![i as u8; 32]).collect()
}

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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::GetResponseReceived {
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

// ── the commitment's wire encoding ───────────────────────────────────────────────

/// A commitment is `keccak256(abi.encode(request))` — Solidity ABI, **not SCALE**.
///
/// `Request::encode()` is an inherent method that shadows the SCALE `Encode` trait
/// (`ismp-2606.1.0/src/router.rs:263-266`), so Rust code reads as if it were SCALE while
/// producing 32-byte-word ABI output. Nothing in this pallet chooses that; it inherits it.
/// But everything off-chain that rebuilds a commitment — the probe, an indexer, a relayer
/// — has to know, and a SCALE-based rebuild fails silently: it hashes fine and the chain
/// answers `UnknownRequest` much later. Pinning the exact bytes here gives those tools a
/// ground truth to test against, and fails loudly if an upstream bump changes the wire.
///
/// The two vectors below are shared with `scripts/hyperbridge/lib/harness.mjs`. Change one
/// side only if you change both.
#[test]
fn commitments_hash_the_abi_encoding_not_scale() {
	let post = Request::Post(PostRequest {
		source: StateMachine::Substrate(*b"orbi"),
		dest: COPROCESSOR,
		nonce: 4,
		from: PALLET_ID_BYTES.to_vec(),
		to: b"demo/mod".to_vec(),
		timeout_timestamp: 0,
		body: alloc::vec![1, 2, 3, 4],
	});
	let get = Request::Get(GetRequest {
		source: StateMachine::Substrate(*b"orbi"),
		dest: COPROCESSOR,
		nonce: 7,
		from: PALLET_ID_BYTES.to_vec(),
		keys: alloc::vec![alloc::vec![0xaa; 32]],
		height: 4242,
		context: alloc::vec![],
		timeout_timestamp: 0,
	});

	new_test_ext().execute_with(|| {
		let hash =
			|r: &Request| alloc::format!("{:?}", hash_request::<pallet_ismp::Pallet<Test>>(r));
		assert_eq!(
			hash(&post),
			"0xe51e536288e74f85fb16bc89fe4d43feb49c15049776de908bb402310bd389bc"
		);
		assert_eq!(
			hash(&get),
			"0xc7f995f640ae3d0ccab18b0ff1280f68d5c906c60e5d62862aa457150d8792ee"
		);

		// The state machines travel as their DISPLAY strings ("SUBSTRATE-orbi",
		// "KUSAMA-4009"), not as SCALE variants — `abi.rs:64-76`. That is why the
		// human-readable form `ismp_queryRequests` returns can be hashed as-is.
		let abi = post.encode();
		assert!(abi.windows(14).any(|w| w == b"SUBSTRATE-orbi"));
		assert!(abi.windows(11).any(|w| w == b"KUSAMA-4009"));
		assert_eq!(
			abi.len() % 32,
			0,
			"abi.encode output is whole 32-byte words"
		);

		// And the SCALE encoding — reachable only through the trait, fully qualified —
		// is a different byte string with a different hash. This is the trap.
		let scale = <Request as Encode>::encode(&post);
		assert_ne!(scale, abi);
		assert_ne!(
			alloc::format!("{:?}", sp_core::H256(sp_io::hashing::keccak_256(&scale))),
			hash(&post),
			"a SCALE-based rebuild must not accidentally reproduce the commitment"
		);
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

// ── Delivery confirmation ────────────────────────────────────────────────────────────

/// Builds a `GetResponse` shaped like the answer to a `confirm_delivery` GET.
fn confirmation_response(
	context: alloc::vec::Vec<u8>,
	value: Option<alloc::vec::Vec<u8>>,
) -> GetResponse {
	GetResponse {
		get: GetRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce: 0,
			from: PALLET_ID_BYTES.to_vec(),
			keys: alloc::vec![crate::receipts::request_receipt_key(
				sp_core::H256::repeat_byte(7)
			)],
			height: 42,
			context,
			timeout_timestamp: 0,
		},
		values: alloc::vec![StorageValue {
			key: crate::receipts::request_receipt_key(sp_core::H256::repeat_byte(7)),
			value,
		}],
	}
}

fn confirmed_events() -> alloc::vec::Vec<(sp_core::H256, alloc::vec::Vec<u8>, u64)> {
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.filter_map(|r| match r.event {
			crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::DeliveryConfirmed {
				commitment,
				relayer,
				height,
			}) => Some((commitment, relayer, height)),
			_ => None,
		})
		.collect()
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
					dest,
					kind,
					..
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

// ── Inbound: the path a real message from Gargantua will take ────────────────────────
//
// `AcceptedSources` was populated on testnet (`KUSAMA-4009`, `EVM-97`) but no inbound
// message has ever arrived — `InboundCount` is 0. These pin the behaviour the first real
// one will hit, so a regression shows up here rather than as a message silently lost on a
// chain we do not control.

/// The event a successful arrival must emit, flattened for assertions.
fn received_events() -> alloc::vec::Vec<(StateMachine, alloc::vec::Vec<u8>, u32, sp_core::H256, u64)>
{
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.filter_map(|r| match r.event {
			crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageReceived {
				source,
				from,
				body_len,
				commitment,
				nonce,
				..
			}) => Some((source, from, body_len, commitment, nonce)),
			_ => None,
		})
		.collect()
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
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
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected {
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
fn accept_source_is_root_only_and_observable() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::accept_source(RuntimeOrigin::signed(1), COPROCESSOR),
			sp_runtime::DispatchError::BadOrigin
		);
		assert_noop!(
			crate::Pallet::<Test>::remove_source(RuntimeOrigin::signed(1), COPROCESSOR),
			sp_runtime::DispatchError::BadOrigin
		);

		assert_ok!(crate::Pallet::<Test>::accept_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		// These two events are the only on-chain record of why inbound traffic from a
		// chain starts or stops — an unaccepted source emits nothing at all.
		let announced = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::SourceAccepted { source })
					if source == COPROCESSOR
			)
		});
		assert!(announced);
	});
}

#[test]
fn accepting_the_same_source_twice_is_harmless() {
	new_test_ext().execute_with(|| {
		// Re-running the setup script must not break a live chain.
		assert_ok!(crate::Pallet::<Test>::accept_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		assert_ok!(crate::Pallet::<Test>::accept_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		assert!(AcceptedSources::<Test>::contains_key(COPROCESSOR));

		assert_ok!(crate::Pallet::<Test>::remove_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		// Removing one that is not there is equally harmless.
		assert_ok!(crate::Pallet::<Test>::remove_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		assert!(!AcceptedSources::<Test>::contains_key(COPROCESSOR));
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

// ── Signed dispatch: who pays, and where it goes ─────────────────────────────────────
//
// `DispatchOrigin` is `EnsureSigned` here, as in the runtime. Accounts 1 and 2 hold
// `100 × worst_case_fee()`, enough to pay for the largest legal message; account 3 holds
// nothing. The charge is taken by this pallet into `TREASURY` and is NOT escrowed in
// `FeeMetadata`, so it is never refunded — which is the whole point: a refundable anti-spam
// charge can be recycled for free every timeout.

use crate::mock::{MESSAGE_BYTE_FEE, MESSAGE_FEE, TREASURY, Timestamp, worst_case_fee};

fn balance(who: u64) -> u128 {
	pallet_balances::Pallet::<Test>::free_balance(who)
}

/// What accounts 1 and 2 start with.
///
/// Read from the constant rather than spelled out at each assertion: these tests are about
/// what a dispatch *costs*, and hard-coding the opening balance made five of them fail the
/// moment the mock was funded differently — a change that says nothing about pricing.
fn funded() -> u128 {
	100 * worst_case_fee()
}

/// Where `pallet-ismp` would park an escrowed fee (`RELAYER_FEE_ACCOUNT`, `ISMPFEES`).
/// Asserted EMPTY throughout: we pass `fee: 0` on the wire.
fn fees_account() -> u64 {
	use sp_runtime::traits::AccountIdConversion;
	pallet_ismp::RELAYER_FEE_ACCOUNT.into_account_truncating()
}

fn ping() -> alloc::vec::Vec<u8> {
	Message::Ping { nonce: 1 }.encode()
}

/// What a signed POST of `body` to the 8-byte `demo/mod` costs.
///
/// A POST is charged its body **plus its module id**, the way Hyperbridge bills one
/// (`encode_post_request` carries every field). Spelled out here rather than at each
/// assertion so the `to` term cannot be dropped from one site and go unnoticed.
fn post_cost(body: &[u8]) -> u128 {
	MESSAGE_FEE + MESSAGE_BYTE_FEE * (body.len() as u128 + b"demo/mod".len() as u128)
}

#[test]
fn an_unsigned_origin_cannot_dispatch() {
	new_test_ext().execute_with(|| {
		// Not Root and not admitted by `DispatchOrigin`: the one shape every call refuses.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::none(),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			),
			sp_runtime::DispatchError::BadOrigin
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::none(),
				COUNTERPARTY,
				get_keys(1),
				10_403_542,
				600,
			),
			sp_runtime::DispatchError::BadOrigin
		);
		assert_noop!(
			crate::Pallet::<Test>::confirm_delivery(
				RuntimeOrigin::none(),
				sp_core::H256::repeat_byte(9),
				42,
				600,
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn a_signed_dispatch_pays_the_treasury_and_escrows_nothing() {
	new_test_ext().execute_with(|| {
		assert_eq!(balance(1), funded());
		assert_eq!(balance(TREASURY), 0);

		let body = ping();
		let expected = post_cost(&body);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			body,
			600,
		));

		// Moved, not burned: what left the signer is exactly what the treasury now holds.
		assert_eq!(balance(1), funded() - expected);
		assert_eq!(balance(TREASURY), expected);
		// And nothing reached upstream's escrow, so nothing can ever be refunded out of it.
		assert_eq!(balance(fees_account()), 0);
		let dispatched = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched { .. })
			)
		});
		assert!(dispatched, "the dispatch itself still happens");
	});
}

#[test]
fn root_dispatches_for_free_and_may_never_expire() {
	new_test_ext().execute_with(|| {
		let pallet = crate::outbound::pallet_account::<Test>();

		// `timeout == 0` is refused from a signer below; Root is the one caller it is for.
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			0,
		));

		assert_eq!(
			balance(pallet),
			0,
			"Root's stand-in account is a label, never debited"
		);
		assert_eq!(balance(TREASURY), 0, "and Root pays the treasury nothing");
		assert_eq!(balance(fees_account()), 0, "and nothing was escrowed");
	});
}

#[test]
fn a_signer_must_let_the_message_expire() {
	new_test_ext().execute_with(|| {
		let max = <Test as crate::Config>::MaxSignedTimeout::get();

		// "Never expires" would lock the fee for good: the only way it comes back is expiry.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				0,
			),
			crate::Error::<Test>::TimeoutRequired
		);
		// Too short to clear two finality rounds: it could only ever expire.
		let min = <Test as crate::Config>::MinSignedTimeout::get();
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				min - 1,
			),
			crate::Error::<Test>::TimeoutTooShort
		);
		// So would a timeout past any horizon a refund is worth waiting for.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				max + 1,
			),
			crate::Error::<Test>::TimeoutTooLong
		);
		// Both bounds themselves are allowed.
		for timeout in [min, max] {
			assert_ok!(crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				timeout,
			));
		}
	});
}

#[test]
fn an_unfunded_signer_is_refused_before_anything_is_written() {
	new_test_ext().execute_with(|| {
		assert_eq!(balance(3), 0);
		let nonce_before = pallet_ismp::Nonce::<Test>::get();

		// A named error, and `assert_noop!` proves no nonce, commitment or event was spent
		// finding out — the dispatcher's own failure would come after all of those.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(3),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			),
			crate::Error::<Test>::InsufficientBalance
		);
		assert_eq!(pallet_ismp::Nonce::<Test>::get(), nonce_before);
	});
}

#[test]
fn an_expired_signed_dispatch_reclaims_its_commitment_but_not_the_charge() {
	new_test_ext().execute_with(|| {
		use ismp::host::IsmpHost;

		// A real clock, so the deadline the dispatcher stamps is one this test can name.
		let now_secs: u64 = 1_700_000_000;
		Timestamp::set_timestamp(now_secs * 1_000);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			600,
		));
		let charge = post_cost(&ping());
		let after_dispatch = balance(1);
		assert_eq!(after_dispatch, funded() - charge);

		// The request exactly as the dispatcher built it, so its commitment is the one on
		// file. `from` is the pallet's module id — the payer lives in the metadata, not here.
		let request = Request::Post(PostRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce: pallet_ismp::Nonce::<Test>::get().saturating_sub(1),
			from: PALLET_ID_BYTES.to_vec(),
			to: b"demo/mod".to_vec(),
			timeout_timestamp: now_secs + 600,
			body: ping(),
		});

		// The two steps upstream's timeout handler takes (`handlers/timeout.rs:332,347`),
		// minus the non-membership proof it verifies first. The proof is upstream's to
		// test; what is ours is that the metadata still names the right payer and the
		// refund reaches them.
		let host = pallet_ismp::Pallet::<Test>::default();
		let meta = host
			.delete_request_commitment(&request)
			.expect("the commitment was on file");
		assert_ok!(IsmpModuleCallback::<Test>::default().on_timeout(request.clone()));
		host.on_request_timeout(&request, meta)
			.expect("refund is a plain transfer from ISMPFEES");

		// Expiry reclaims the commitment — and nothing else. The charge was taken by this
		// pallet, not escrowed upstream, so there is nothing for `on_request_timeout` to
		// hand back: `fee: 0` on the wire means its refund branch never fires. That is
		// deliberate. A charge that comes back on expiry is a charge a spammer recycles.
		assert_eq!(balance(1), after_dispatch, "the charge stays paid");
		assert_eq!(balance(TREASURY), charge, "and stays with the treasury");
		assert_eq!(balance(fees_account()), 0, "nothing was ever escrowed");
	});
}

#[test]
fn a_get_and_a_confirmation_cost_the_same_fee() {
	new_test_ext().execute_with(|| {
		// A GET is priced on its keys, the equivalent of a POST's body.
		let keys = get_keys(1);
		let get_cost =
			MESSAGE_FEE + MESSAGE_BYTE_FEE * keys.iter().map(|k| k.len() as u128).sum::<u128>();
		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			keys,
			10_403_542,
			600,
		));
		assert_eq!(balance(1), funded() - get_cost);

		// `confirm_delivery` is a one-key GET — but it also carries a 32-byte context, the
		// commitment it is confirming, and that context travels on the wire and comes back
		// inside `GetResponse.get`. So it costs the key AND the context.
		//
		// This assertion used to count the key alone, which made the undercharge look like
		// correct behaviour: the signer paid for 47 bytes and sent 79.
		let confirm_keys = crate::receipts::confirmation_keys(sp_core::H256::repeat_byte(9));
		let confirm_context = 32u128;
		let confirm_cost = MESSAGE_FEE
			+ MESSAGE_BYTE_FEE
				* (confirm_keys.iter().map(|k| k.len() as u128).sum::<u128>() + confirm_context);
		assert_ok!(crate::Pallet::<Test>::confirm_delivery(
			RuntimeOrigin::signed(1),
			sp_core::H256::repeat_byte(9),
			42,
			600,
		));
		assert_eq!(balance(1), funded() - get_cost - confirm_cost);
		assert_eq!(balance(TREASURY), get_cost + confirm_cost);
		assert_eq!(balance(fees_account()), 0, "still nothing escrowed");
	});
}

#[test]
fn two_signers_sending_the_same_body_do_not_collide() {
	new_test_ext().execute_with(|| {
		// Identical args from two accounts: `impls.rs:93` rejects a duplicate commitment,
		// and the nonce is what keeps these two apart. Both must land.
		for who in [1u64, 2] {
			assert_ok!(crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(who),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			));
		}
		assert_eq!(pallet_ismp::Nonce::<Test>::get(), 2);
		let each = post_cost(&ping());
		assert_eq!(balance(TREASURY), 2 * each);
	});
}

#[test]
fn a_bigger_message_costs_more() {
	new_test_ext().execute_with(|| {
		// A flat fee prices one byte the same as a full body, while the cost this chain and
		// its relayer bear scales with size. Hyperbridge prices its own outbound traffic by
		// the byte for the same reason (`pallet-bandwidth`).
		let small = Message::Data {
			nonce: 1,
			data: alloc::vec![],
		}
		.encode();
		let large = Message::Data {
			nonce: 1,
			data: alloc::vec![0u8; 500],
		}
		.encode();

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			small.clone(),
			600,
		));
		let cheap = balance(TREASURY);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(2),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			large.clone(),
			600,
		));
		let dear = balance(TREASURY) - cheap;

		assert_eq!(cheap, post_cost(&small));
		assert_eq!(dear, post_cost(&large));
		assert!(dear > cheap, "{dear} should exceed {cheap}");
	});
}

#[test]
fn root_can_pause_signed_dispatch_without_stopping_its_own() {
	new_test_ext().execute_with(|| {
		assert_ok!(crate::Pallet::<Test>::set_outbound_paused(
			RuntimeOrigin::root(),
			true
		));
		assert!(crate::OutboundPaused::<Test>::get());

		// Every signed path is closed…
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			),
			crate::Error::<Test>::OutboundPaused
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				get_keys(1),
				10_403_542,
				600,
			),
			crate::Error::<Test>::OutboundPaused
		);
		assert_noop!(
			crate::Pallet::<Test>::confirm_delivery(
				RuntimeOrigin::signed(1),
				sp_core::H256::repeat_byte(9),
				42,
				600,
			),
			crate::Error::<Test>::OutboundPaused
		);

		// …while this chain's own automation is untouched, which is why the check lives in
		// the signed branch rather than at the top of the extrinsic.
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			0,
		));
		assert_ok!(crate::Pallet::<Test>::confirm_delivery(
			RuntimeOrigin::root(),
			sp_core::H256::repeat_byte(9),
			42,
			600
		));

		// And it lifts.
		assert_ok!(crate::Pallet::<Test>::set_outbound_paused(
			RuntimeOrigin::root(),
			false
		));
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			600,
		));
	});
}

#[test]
fn pausing_is_root_only() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::set_outbound_paused(RuntimeOrigin::signed(1), true),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn root_can_reprice_a_message_without_a_runtime_upgrade() {
	new_test_ext().execute_with(|| {
		// The whole reason the fee is storage and not a constant: the right price tracks
		// what the token is worth, and a constant in the WASM cannot follow it. Correcting
		// one would otherwise mean a build and a `setCode`.
		assert_eq!(crate::MessageFee::<Test>::get(), MESSAGE_FEE);
		assert_eq!(crate::MessageByteFee::<Test>::get(), MESSAGE_BYTE_FEE);

		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			5 * MESSAGE_FEE,
			2 * MESSAGE_BYTE_FEE,
		));

		let body = ping();
		let expected = 5 * MESSAGE_FEE
			+ 2 * MESSAGE_BYTE_FEE * (body.len() as u128 + b"demo/mod".len() as u128);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			body,
			600,
		));
		assert_eq!(
			balance(TREASURY),
			expected,
			"the new price took effect at once"
		);
	});
}

#[test]
fn a_repricing_is_capped_on_what_the_largest_message_would_cost() {
	new_test_ext().execute_with(|| {
		// The ceiling is what keeps the dial from becoming a foot-gun: a mistyped value
		// would otherwise price dispatch out of reach until the next runtime upgrade.
		use frame_support::traits::Get;
		let max = <Test as crate::Config>::MaxMessageFee::get();
		// The ceiling's size term is the largest of EVERY dispatch shape, not a body's: a
		// GET is priced on the sum of its key lengths, which can exceed `MaxBodyLen`.
		let worst_size = crate::outbound::max_chargeable_size::<Test>() as u128;

		assert_noop!(
			crate::Pallet::<Test>::set_message_fee(RuntimeOrigin::root(), max + 1, 0),
			crate::Error::<Test>::MessageFeeTooHigh
		);

		// The bound is on the WORST CASE, not on each term: a per-byte value at the flat
		// ceiling would price a full body at `MaxBodyLen` times the cap, which is the very
		// outcome the ceiling exists to prevent. Transposing the two arguments — they have
		// the same type — is the easy way to get there, so it must be refused.
		assert_noop!(
			crate::Pallet::<Test>::set_message_fee(RuntimeOrigin::root(), 0, max),
			crate::Error::<Test>::MessageFeeTooHigh
		);
		// One planck per byte over the budget is still over it.
		assert_noop!(
			crate::Pallet::<Test>::set_message_fee(RuntimeOrigin::root(), 0, max / worst_size + 1),
			crate::Error::<Test>::MessageFeeTooHigh
		);

		// A per-byte value whose worst case fits is allowed…
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			0,
			max / worst_size
		));
		// …as is the flat ceiling on its own.
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			max,
			0
		));

		// And now the part that matters: what the chain ACTUALLY charges for the largest
		// message of each shape, measured rather than recomputed.
		//
		// The previous version of this test asserted `fee + byte_fee × MaxBodyLen <= max`
		// — the same expression `set_message_fee` itself evaluates, with the same term. It
		// was a tautology, and it held while the largest GET cost sixteen times the ceiling,
		// because a GET is charged on its keys and `MaxBodyLen` never described them.
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			0,
			max / worst_size
		));

		let keys = <<Test as crate::Config>::MaxGetKeys as Get<u32>>::get();
		let key_len = <<Test as crate::Config>::MaxGetKeyLen as Get<u32>>::get();
		let before = balance(TREASURY);
		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			alloc::vec![alloc::vec![0u8; key_len as usize]; keys as usize],
			10_403_542,
			600,
		));
		let charged = balance(TREASURY) - before;
		assert!(
			charged <= max,
			"the largest GET cost {charged}, above the ceiling {max}"
		);

		let before = balance(TREASURY);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			alloc::vec![0u8; <<Test as crate::Config>::MaxBodyLen as Get<u32>>::get() as usize],
			600,
		));
		let charged = balance(TREASURY) - before;
		assert!(
			charged <= max,
			"the largest POST cost {charged}, above the ceiling {max}"
		);
	});
}

#[test]
fn the_largest_legal_message_can_actually_be_paid_for() {
	new_test_ext().execute_with(|| {
		// Every size-boundary test in this file used to run as Root — the path that never
		// pays — because the mock funded accounts with `10 × MESSAGE_FEE` while a full body
		// costs `MESSAGE_FEE + MESSAGE_BYTE_FEE × MaxBodyLen`. The largest signed message
		// was literally unaffordable, so nothing checked that the bound and the charge agree.
		use frame_support::traits::Get;
		let body_max = <<Test as crate::Config>::MaxBodyLen as Get<u32>>::get();
		let before = balance(TREASURY);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			alloc::vec![0u8; body_max as usize],
			600,
		));

		assert_eq!(
			balance(TREASURY) - before,
			post_cost(&alloc::vec![0u8; body_max as usize]),
			"a full-length body is charged flat + per byte over the whole body"
		);

		// One byte more is refused on size, not on funds — the signer can still afford it.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				alloc::vec![0u8; body_max as usize + 1],
				600,
			),
			crate::Error::<Test>::BodyTooLarge
		);
	});
}

#[test]
fn a_signed_get_is_bounded_by_the_same_guards_as_root() {
	new_test_ext().execute_with(|| {
		// Every guard in `outbound::get` was only ever tested from Root. Moving them into
		// the paying branch of `fee_for` — or wrapping them in `if payer.is_none()` — would
		// leave signed users unbounded while the suite stayed green, which inverts what the
		// bounds are for: they cap work imposed on a REMOTE chain and a relayer, and the
		// signed caller is the one who is not us.
		use frame_support::traits::Get;
		let too_many = <<Test as crate::Config>::MaxGetKeys as Get<u32>>::get() as usize + 1;
		let signed = || RuntimeOrigin::signed(1);

		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(signed(), COUNTERPARTY, alloc::vec![], 42, 600),
			crate::Error::<Test>::NoKeysRequested
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				signed(),
				COUNTERPARTY,
				get_keys(too_many),
				42,
				600
			),
			crate::Error::<Test>::TooManyKeys
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(signed(), COUNTERPARTY, get_keys(1), 0, 600),
			crate::Error::<Test>::InvalidGetHeight
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				signed(),
				StateMachine::Substrate(*b"orbi"),
				get_keys(1),
				42,
				600
			),
			crate::Error::<Test>::DestinationIsSelf
		);

		// And none of those cost the signer anything: each is refused before the charge.
		assert_eq!(balance(TREASURY), 0, "a refused GET is never charged for");
	});
}

#[test]
fn a_signer_may_spend_their_very_last_planck() {
	new_test_ext().execute_with(|| {
		// `ExistentialDeposit` is zero on this chain (`configs/system.rs:65`), which is what
		// `fee_for` cites to justify `Preservation::Expendable`: there is no minimum to keep
		// back, so an account may legitimately pay its whole balance and be reaped.
		//
		// This is the test that holds that justification to account. The mock used to
		// inherit the balances prelude's ED of 1, under which no test could drain an account
		// at all — so `Expendable` could have been `Preserve` with the suite still green,
		// and a signer whose balance was exactly the fee would have been refused.
		let body = ping();
		let exact = post_cost(&body);

		// Account 3 starts empty. Give it exactly one message's worth, not a planck more.
		assert_ok!(pallet_balances::Pallet::<Test>::force_set_balance(
			RuntimeOrigin::root(),
			3,
			exact
		));
		assert_eq!(balance(3), exact);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(3),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			body,
			600,
		));

		assert_eq!(balance(3), 0, "the whole balance was spendable");
		assert_eq!(balance(TREASURY), exact);

		// And now genuinely broke: the next one cannot be paid for.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(3),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			),
			crate::Error::<Test>::InsufficientBalance
		);
	});
}

#[test]
fn context_bytes_are_charged_for_like_keys() {
	new_test_ext().execute_with(|| {
		// `context` travels on the wire and comes back inside `GetResponse.get`, which is why
		// `outbound::get` bounds it at all. For a while it was bounded and NOT charged, so the
		// larger half of a GET's payload was free: at runtime values a maximal GET carried
		// 2,048 bytes of keys and up to 8,192 of context, and only the keys were priced.
		//
		// Two GETs with identical keys and different context lengths must therefore cost
		// different amounts. Dispatched through `outbound::get` directly because no extrinsic
		// exposes `context` today — which is exactly what keeps this from being a live hole,
		// and exactly why it needs pinning before one does.
		let keys = get_keys(1);
		let key_bytes: u128 = keys.iter().map(|k| k.len() as u128).sum();

		let before = balance(TREASURY);
		assert_ok!(crate::outbound::get::<Test>(
			Some(1),
			COUNTERPARTY,
			keys.clone(),
			42,
			600,
			alloc::vec![],
		));
		let bare = balance(TREASURY) - before;
		assert_eq!(bare, MESSAGE_FEE + MESSAGE_BYTE_FEE * key_bytes);

		let before = balance(TREASURY);
		assert_ok!(crate::outbound::get::<Test>(
			Some(1),
			COUNTERPARTY,
			keys,
			42,
			600,
			alloc::vec![7u8; 100],
		));
		let with_context = balance(TREASURY) - before;

		assert_eq!(
			with_context - bare,
			MESSAGE_BYTE_FEE * 100,
			"a hundred context bytes must cost a hundred bytes' worth"
		);
	});
}

/// The guard the header comment in `weights.rs` asks for, and cannot itself provide.
///
/// The benchmark CLI has a bug that emits a `proof_size` around 2.5 EXABYTES for
/// `dispatch_post` — `2_585_700_789_447_993_344` on one run, `8_126_544_059_662_763_008` on
/// the next, non-deterministically. `weights.rs` documents it at length and carries a
/// hand-corrected 3550. But **the generator overwrites that header on every regeneration**,
/// so the only thing standing between a fresh run and an absurd value is a comment that the
/// run itself deletes.
///
/// This test survives regeneration. The pallet's real `proof_size` values span 1504 to 3606,
/// and the bad ones are ~10^18 — sixteen orders apart, so a generous ceiling separates them
/// with no risk of a false alarm. Anyone regenerating gets a failing test rather than a
/// runtime that believes one extrinsic consumes every block's proof budget.
#[test]
fn declared_proof_sizes_stay_within_a_sane_ceiling() {
	use frame_support::traits::Get;

	// The intercepts sit in 1504-3606, but the per-component terms dominate at the top of a
	// range: `dispatch_post(8192)` legitimately declares `3550 + 8192 x 21` = 175,582, and
	// `dispatch_get` at the runtime's 16 keys reaches `3550 + 16 x 5376` = 89,566.
	//
	// The ceiling inside `check` is ten million: ~57x above every honest value, eleven orders
	// below a corrupted one (~10^18). That gap is what makes this test impossible to trip by
	// accident and impossible for the real bug to slip through.

	let body_max = <<Test as crate::Config>::MaxBodyLen as Get<u32>>::get();
	let keys_max = <<Test as crate::Config>::MaxGetKeys as Get<u32>>::get();

	// BOTH impls. The generator writes the same numbers into `SubstrateWeight` and into `()`,
	// and the runtime uses `SubstrateWeight` (`configs/ismp/mod.rs`) while this mock uses
	// `()`. Checking only the one the mock happens to use would leave the one production
	// actually runs unguarded — and an earlier draft of this test did exactly that, which a
	// mutation caught: injecting the exabyte value into `SubstrateWeight` left it green.
	fn check<W: crate::weights::WeightInfo>(label: &str, body_max: u32, keys_max: u32) {
		const CEILING: u64 = 10_000_000;

		// Both ends of every component: the corruption lands in the intercept, so it shows at
		// zero as readily as at the maximum.
		for b in [0, body_max] {
			let w = W::dispatch_post(b);
			assert!(
				w.proof_size() < CEILING,
				"{label}: dispatch_post({b}) declares proof_size {} — regenerated with an \
				 unfixed CLI? See the header of weights.rs; the corrected value is 3550",
				w.proof_size()
			);
			let w = W::on_accept(b);
			assert!(
				w.proof_size() < CEILING,
				"{label}: on_accept({b}): {}",
				w.proof_size()
			);
		}

		for k in [1, keys_max] {
			let w = W::dispatch_get(k);
			assert!(
				w.proof_size() < CEILING,
				"{label}: dispatch_get({k}) declares proof_size {} — it walks the same \
				 RequestCommitments path as dispatch_post and is exposed to the same bug",
				w.proof_size()
			);
		}

		for w in [
			W::accept_source(),
			W::remove_source(),
			W::set_message_fee(),
			W::set_outbound_paused(),
			W::on_timeout(),
			W::on_response(0),
			// The component's own maximum, not a literal: the benchmark range is
			// `Linear<0, MaxGetKeys>`, and 64 was left over from an older hardcoded bound.
			W::on_response(keys_max),
		] {
			assert!(
				w.proof_size() < CEILING,
				"{label}: proof_size {}",
				w.proof_size()
			);
		}
	}

	check::<()>("()", body_max, keys_max);
	check::<crate::weights::SubstrateWeight<Test>>("SubstrateWeight", body_max, keys_max);
}

#[test]
fn the_module_id_is_charged_for_like_the_body() {
	new_test_ext().execute_with(|| {
		// Hyperbridge bills a POST by `encode_post_request(&request).len()`
		// (`gargantua/src/ismp.rs:383`), and that encoding carries `to` along with everything
		// else (`modules/ismp/core/src/abi.rs:64-76`). Charging the body alone left the
		// module id free while a GET's context was charged — an asymmetry against upstream's
		// own basis for billing.
		//
		// `ModuleId::from_bytes` admits exactly three lengths, so two of them priced
		// differently is the whole proof: same body, longer id, higher charge.
		let body = ping();

		let before = balance(TREASURY);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(), // 8 bytes: a pallet id
			body.clone(),
			600,
		));
		let short_id = balance(TREASURY) - before;

		let before = balance(TREASURY);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			alloc::vec![9u8; 32], // 32 bytes: an account id
			body.clone(),
			600,
		));
		let long_id = balance(TREASURY) - before;

		assert_eq!(
			long_id - short_id,
			MESSAGE_BYTE_FEE * 24,
			"a 32-byte id must cost 24 bytes more than an 8-byte one"
		);
		assert_eq!(short_id, post_cost(&body));
	});
}

#[test]
fn a_dispatch_that_fails_refunds_the_charge() {
	new_test_ext().execute_with(|| {
		// The charge is taken before the dispatch, so the one place money and failure meet
		// is a dispatcher error after a successful transfer. Extrinsics are transactional,
		// which means the transfer unwinds — but nothing pinned that until now.
		//
		// Forced by making the dispatcher see a duplicate commitment (`impls.rs:92-94`).
		// Rather than recompute the hash here — which would re-derive the dispatcher's own
		// encoding and could drift from it — send one message, take the commitment the
		// chain actually recorded, and put it back. The nonce is rewound so the next
		// dispatch rebuilds the identical request.
		let body = ping();
		let send = || {
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				body.clone(),
				600,
			)
		};
		assert_ok!(send());
		let commitment = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
					commitment,
					..
				}) => Some(commitment),
				_ => None,
			})
			.expect("the first dispatch emitted one");
		let meta = pallet_ismp::child_trie::RequestCommitments::<Test>::get(commitment)
			.expect("and recorded it");
		let nonce_before = pallet_ismp::Nonce::<Test>::get();
		pallet_ismp::Nonce::<Test>::put(nonce_before - 1);
		pallet_ismp::child_trie::RequestCommitments::<Test>::insert(commitment, meta);

		let before = balance(1);
		let treasury_before = balance(TREASURY);
		assert_noop!(send(), crate::Error::<Test>::DispatchFailed);
		// `assert_noop!` already proves no storage changed; naming the balances says which
		// storage the reader should care about — the charge is taken BEFORE the dispatch,
		// so this is the one place money and failure meet.
		assert_eq!(balance(1), before, "the charge unwound with the dispatch");
		assert_eq!(balance(TREASURY), treasury_before);
	});
}

#[test]
fn repricing_and_pausing_announce_themselves() {
	new_test_ext().execute_with(|| {
		// Both are root levers whose effect is invisible in a block unless they emit: an
		// indexer watching for a price change has nothing else to watch.
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			7,
			11
		));
		assert_ok!(crate::Pallet::<Test>::set_outbound_paused(
			RuntimeOrigin::root(),
			true
		));

		let events = frame_system::Pallet::<Test>::events();
		assert!(events.iter().any(|r| matches!(
			r.event,
			crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::MessageFeeUpdated {
				fee: 7,
				byte_fee: 11
			})
		)));
		assert!(events.iter().any(|r| matches!(
			r.event,
			crate::mock::RuntimeEvent::IsmpMessaging(crate::Event::OutboundPauseSet {
				paused: true
			})
		)));
	});
}

#[test]
fn repricing_is_root_only() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::set_message_fee(RuntimeOrigin::signed(1), 0, 0),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn a_zero_fee_is_allowed_and_charges_nothing() {
	new_test_ext().execute_with(|| {
		// Root may price dispatch at zero — the anti-spam charge is a policy dial, not a
		// protocol requirement, and `dispatch_request` skips the transfer when it is zero.
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			0,
			0
		));
		let before = balance(1);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			600,
		));
		assert_eq!(balance(1), before);
		assert_eq!(balance(TREASURY), 0);
	});
}
