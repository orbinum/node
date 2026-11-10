//! Fixtures the tests share: the counterparties, request builders, event readers and
//! balance helpers.

use crate::{PALLET_ID_BYTES, payload::Message, tests::mock::*};
use ismp::{
	host::StateMachine,
	router::{GetRequest, GetResponse, PostRequest, StorageValue},
};
use scale_codec::Encode;

/// An arbitrary counterparty reached *through* Hyperbridge, not Hyperbridge itself.
/// Nothing about this pallet is specific to any one chain — that is the point.
pub const COUNTERPARTY: StateMachine = StateMachine::Kusama(1000);
/// Hyperbridge's testnet deployment — the coprocessor.
pub const COPROCESSOR: StateMachine = StateMachine::Kusama(4009);

pub fn post_from(source: StateMachine, body: alloc::vec::Vec<u8>) -> PostRequest {
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

/// A fixed wall clock for the dispatch tests, in unix SECONDS.
pub const NOW_SECS: u64 = 1_788_900_000;

/// Reads the commitment out of whichever of our events carries one.
///
/// Matching the variant by name would let a test pass while the *other* events lost their
/// commitment, so this deliberately accepts any of them.
pub fn emitted_commitment() -> Option<sp_core::H256> {
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.find_map(|r| match r.event {
			RuntimeEvent::IsmpMessaging(crate::Event::MessageReceived { commitment, .. })
			| RuntimeEvent::IsmpMessaging(crate::Event::MessageRejected { commitment, .. })
			| RuntimeEvent::IsmpMessaging(crate::Event::GetResponseReceived {
				commitment, ..
			})
			| RuntimeEvent::IsmpMessaging(crate::Event::RequestTimedOut { commitment, .. }) => {
				Some(commitment)
			}
			_ => None,
		})
}

/// The `RequestDispatched` payload, for the tests that assert on its new fields.
pub fn dispatched_event() -> Option<(sp_core::H256, u64, u64, u32, crate::RequestKind)> {
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.find_map(|r| match r.event {
			RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
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

/// The event a successful arrival must emit, flattened for assertions.
pub fn received_events()
-> alloc::vec::Vec<(StateMachine, alloc::vec::Vec<u8>, u32, sp_core::H256, u64)> {
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::IsmpMessaging(crate::Event::MessageReceived {
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

/// A GET to the counterparty with `n` distinct keys.
pub fn get_keys(n: usize) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
	(0..n).map(|i| alloc::vec![i as u8; 32]).collect()
}

/// Builds a `GetResponse` shaped like the answer to a `confirm_delivery` GET.
pub fn confirmation_response(
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

pub fn confirmed_events() -> alloc::vec::Vec<(sp_core::H256, alloc::vec::Vec<u8>, u64)> {
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::IsmpMessaging(crate::Event::DeliveryConfirmed {
				commitment,
				relayer,
				height,
			}) => Some((commitment, relayer, height)),
			_ => None,
		})
		.collect()
}

pub fn balance(who: u64) -> u128 {
	pallet_balances::Pallet::<Test>::free_balance(who)
}

/// What accounts 1 and 2 start with.
///
/// Read from the constant rather than spelled out at each assertion: these tests are about
/// what a dispatch *costs*, and hard-coding the opening balance made five of them fail the
/// moment the mock was funded differently — a change that says nothing about pricing.
pub fn funded() -> u128 {
	100 * worst_case_fee()
}

/// Where `pallet-ismp` would park an escrowed fee (`RELAYER_FEE_ACCOUNT`, `ISMPFEES`).
/// Asserted EMPTY throughout: we pass `fee: 0` on the wire.
pub fn fees_account() -> u64 {
	use sp_runtime::traits::AccountIdConversion;
	pallet_ismp::RELAYER_FEE_ACCOUNT.into_account_truncating()
}

pub fn ping() -> alloc::vec::Vec<u8> {
	Message::Ping { nonce: 1 }.encode()
}

/// What a signed POST of `body` to the 8-byte `demo/mod` costs.
///
/// A POST is charged its body **plus its module id**, the way Hyperbridge bills one
/// (`encode_post_request` carries every field). Spelled out here rather than at each
/// assertion so the `to` term cannot be dropped from one site and go unnoticed.
pub fn post_cost(body: &[u8]) -> u128 {
	MESSAGE_FEE + MESSAGE_BYTE_FEE * (body.len() as u128 + b"demo/mod".len() as u128)
}
