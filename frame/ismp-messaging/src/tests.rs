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
fn dispatch_get_rejects_an_unprovable_height() {
	new_test_ext().execute_with(|| {
		// `handlers/response.rs:71` compares the proof height for EQUALITY, so height 0 is
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
fn dispatch_get_rejects_non_root() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				get_keys(1),
				10_403_542,
				0,
			),
			sp_runtime::DispatchError::BadOrigin
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
