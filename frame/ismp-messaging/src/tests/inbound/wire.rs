//! The wire format: the module id, the message codec and the commitment's ABI
//! encoding. A mistake in any of them goes unnoticed locally and breaks every message.

use crate::tests::util::*;
use crate::{PALLET_ID, PALLET_ID_BYTES, payload::Message, tests::mock::*};
use ismp::{
	host::StateMachine,
	messaging::hash_request,
	router::{GetRequest, PostRequest, Request},
};
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
